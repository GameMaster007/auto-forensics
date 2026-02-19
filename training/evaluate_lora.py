from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any

import torch
from peft import PeftModel
from transformers import AutoModelForCausalLM, AutoTokenizer


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            stripped = line.strip()
            if not stripped:
                continue
            rows.append(json.loads(stripped))
    return rows


def _required_keys(task: str) -> set[str]:
    if task == "first_pass":
        return {"observations", "likely_behaviors", "preliminary_risk"}
    if task == "second_pass":
        return {"findings", "timeline_hints", "attack_chain"}
    return {"assessment", "priority_actions", "attack_chain", "confidence"}


def _strip_assistant(messages: list[dict[str, str]]) -> list[dict[str, str]]:
    cleaned: list[dict[str, str]] = []
    for item in messages:
        if item.get("role") == "assistant":
            break
        cleaned.append({"role": item.get("role", "user"), "content": item.get("content", "")})
    return cleaned


def _render_prompt(tokenizer: AutoTokenizer, messages: list[dict[str, str]]) -> str:
    if hasattr(tokenizer, "apply_chat_template"):
        return tokenizer.apply_chat_template(messages, tokenize=False, add_generation_prompt=True)

    lines = []
    for msg in messages:
        role = msg.get("role", "user")
        content = msg.get("content", "")
        lines.append(f"<{role}>\n{content}\n</{role}>")
    lines.append("<assistant>\n")
    return "\n".join(lines)


def _parse_json_output(text: str) -> dict[str, Any] | None:
    cleaned = text.strip()
    if cleaned.startswith("```"):
        cleaned = re.sub(r"^```(?:json)?", "", cleaned, flags=re.IGNORECASE).strip()
        cleaned = re.sub(r"```$", "", cleaned).strip()

    try:
        parsed = json.loads(cleaned)
        if isinstance(parsed, dict):
            return parsed
    except json.JSONDecodeError:
        pass

    start = cleaned.find("{")
    end = cleaned.rfind("}")
    if start == -1 or end == -1 or end <= start:
        return None

    candidate = cleaned[start : end + 1]
    try:
        parsed = json.loads(candidate)
        if isinstance(parsed, dict):
            return parsed
    except json.JSONDecodeError:
        return None
    return None


def main() -> None:
    parser = argparse.ArgumentParser(description="Evaluate JSON-schema fitness of fine-tuned adapter.")
    parser.add_argument("--base-model", required=True, help="HF base model id used for training.")
    parser.add_argument("--adapter-dir", type=Path, required=True, help="LoRA adapter output directory.")
    parser.add_argument(
        "--eval-file",
        type=Path,
        default=Path("training") / "data" / "valid.jsonl",
        help="Evaluation dataset JSONL.",
    )
    parser.add_argument("--samples", type=int, default=60, help="Max examples to evaluate.")
    parser.add_argument("--max-new-tokens", type=int, default=320)
    args = parser.parse_args()

    if not args.eval_file.exists():
        raise SystemExit(f"Evaluation file not found: {args.eval_file}")

    dtype = torch.float16 if torch.cuda.is_available() else torch.float32
    tokenizer = AutoTokenizer.from_pretrained(args.base_model, use_fast=True)
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token

    base = AutoModelForCausalLM.from_pretrained(
        args.base_model,
        torch_dtype=dtype,
        device_map="auto" if torch.cuda.is_available() else None,
    )
    model = PeftModel.from_pretrained(base, str(args.adapter_dir))
    model.eval()

    rows = _read_jsonl(args.eval_file)[: max(1, args.samples)]
    total = len(rows)
    parsed_ok = 0
    schema_ok = 0
    range_ok = 0
    failures: list[dict[str, Any]] = []

    for idx, row in enumerate(rows):
        task = str(row.get("task", "summary"))
        messages = row.get("messages", [])
        if not isinstance(messages, list):
            continue

        prompt_messages = _strip_assistant(messages)
        prompt_text = _render_prompt(tokenizer, prompt_messages)
        inputs = tokenizer(prompt_text, return_tensors="pt").to(model.device)

        with torch.no_grad():
            generated = model.generate(
                **inputs,
                max_new_tokens=args.max_new_tokens,
                do_sample=False,
                eos_token_id=tokenizer.eos_token_id,
                pad_token_id=tokenizer.pad_token_id,
            )

        new_tokens = generated[0][inputs["input_ids"].shape[1] :]
        text = tokenizer.decode(new_tokens, skip_special_tokens=True).strip()

        parsed = _parse_json_output(text)
        if parsed is not None:
            parsed_ok += 1

        if parsed is None:
            failures.append({"index": idx, "task": task, "reason": "json_parse_failed", "output": text[:500]})
            continue

        keys = _required_keys(task)
        if keys.issubset(set(parsed.keys())):
            schema_ok += 1
        else:
            failures.append(
                {
                    "index": idx,
                    "task": task,
                    "reason": "schema_missing_keys",
                    "missing": sorted(keys.difference(set(parsed.keys()))),
                    "output": text[:500],
                }
            )
            continue

        numeric_valid = True
        if task == "first_pass":
            risk = parsed.get("preliminary_risk", 0.0)
            numeric_valid = isinstance(risk, (int, float)) and 0.0 <= float(risk) <= 1.0
        elif task == "second_pass":
            hints = parsed.get("timeline_hints", [])
            if isinstance(hints, list):
                for hint in hints:
                    if not isinstance(hint, dict):
                        numeric_valid = False
                        break
                    score = hint.get("risk_score", 0.0)
                    if not isinstance(score, (int, float)) or not (0.0 <= float(score) <= 10.0):
                        numeric_valid = False
                        break
            else:
                numeric_valid = False
        else:
            conf = parsed.get("confidence", 0.0)
            numeric_valid = isinstance(conf, (int, float)) and 0.0 <= float(conf) <= 1.0

        if numeric_valid:
            range_ok += 1
        else:
            failures.append({"index": idx, "task": task, "reason": "numeric_range_failed", "output": text[:500]})

    result = {
        "samples": total,
        "json_parse_rate": round(parsed_ok / max(1, total), 4),
        "schema_coverage_rate": round(schema_ok / max(1, total), 4),
        "numeric_range_rate": round(range_ok / max(1, total), 4),
        "failures": failures[:20],
    }
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
