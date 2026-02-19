from __future__ import annotations

import argparse
import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import torch
from datasets import Dataset
from peft import LoraConfig, get_peft_model, prepare_model_for_kbit_training
from transformers import (
    AutoModelForCausalLM,
    AutoTokenizer,
    BitsAndBytesConfig,
    DataCollatorForLanguageModeling,
    Trainer,
    TrainingArguments,
)


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            stripped = line.strip()
            if not stripped:
                continue
            rows.append(json.loads(stripped))
    return rows


def _messages_to_text(tokenizer: AutoTokenizer, messages: list[dict[str, str]]) -> str:
    if hasattr(tokenizer, "apply_chat_template"):
        return tokenizer.apply_chat_template(messages, tokenize=False, add_generation_prompt=False)

    lines = []
    for msg in messages:
        role = msg.get("role", "user")
        content = msg.get("content", "")
        lines.append(f"<{role}>\n{content}\n</{role}>")
    return "\n".join(lines)


def _target_modules(model_name: str) -> list[str]:
    name = model_name.lower()
    if "gpt-oss" in name:
        return ["q_proj", "k_proj", "v_proj", "o_proj", "gate_proj", "up_proj", "down_proj"]
    if "gemma" in name:
        return ["q_proj", "k_proj", "v_proj", "o_proj", "gate_proj", "up_proj", "down_proj"]
    if "qwen" in name:
        return ["q_proj", "k_proj", "v_proj", "o_proj", "gate_proj", "up_proj", "down_proj"]
    return ["q_proj", "k_proj", "v_proj", "o_proj"]


def _build_tokenized_dataset(
    rows: list[dict[str, Any]],
    tokenizer: AutoTokenizer,
    max_length: int,
) -> Dataset:
    texts: list[str] = []
    for row in rows:
        messages = row.get("messages", [])
        if not isinstance(messages, list) or not messages:
            continue
        text = _messages_to_text(tokenizer, messages)
        texts.append(text)

    dataset = Dataset.from_dict({"text": texts})

    def tokenize_batch(batch: dict[str, list[str]]) -> dict[str, Any]:
        tokenized = tokenizer(
            batch["text"],
            truncation=True,
            max_length=max_length,
            padding=False,
        )
        tokenized["labels"] = [ids[:] for ids in tokenized["input_ids"]]
        return tokenized

    return dataset.map(tokenize_batch, batched=True, remove_columns=["text"])


@dataclass(slots=True)
class TrainConfig:
    base_model: str
    train_file: Path
    valid_file: Path
    output_dir: Path
    epochs: float
    learning_rate: float
    batch_size: int
    grad_accum_steps: int
    max_seq_length: int
    logging_steps: int
    eval_steps: int
    save_steps: int
    lora_r: int
    lora_alpha: int
    lora_dropout: float
    use_4bit: bool
    seed: int


def _load_model_and_tokenizer(cfg: TrainConfig) -> tuple[Any, AutoTokenizer, bool]:
    tokenizer = AutoTokenizer.from_pretrained(cfg.base_model, use_fast=True)
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token

    use_cuda = torch.cuda.is_available()
    use_4bit = cfg.use_4bit and use_cuda
    quant_config = None

    if use_4bit:
        quant_config = BitsAndBytesConfig(
            load_in_4bit=True,
            bnb_4bit_quant_type="nf4",
            bnb_4bit_use_double_quant=True,
            bnb_4bit_compute_dtype=torch.float16,
        )

    dtype = torch.float16 if use_cuda else torch.float32
    model = AutoModelForCausalLM.from_pretrained(
        cfg.base_model,
        torch_dtype=dtype,
        quantization_config=quant_config,
        device_map="auto" if use_cuda else None,
    )
    model.config.use_cache = False

    quantized = quant_config is not None
    if quantized:
        model = prepare_model_for_kbit_training(model)

    lora_config = LoraConfig(
        r=cfg.lora_r,
        lora_alpha=cfg.lora_alpha,
        lora_dropout=cfg.lora_dropout,
        bias="none",
        task_type="CAUSAL_LM",
        target_modules=_target_modules(cfg.base_model),
    )
    model = get_peft_model(model, lora_config)
    return model, tokenizer, quantized


def _train(cfg: TrainConfig) -> dict[str, Any]:
    model, tokenizer, quantized = _load_model_and_tokenizer(cfg)
    train_rows = _read_jsonl(cfg.train_file)
    valid_rows = _read_jsonl(cfg.valid_file)

    train_ds = _build_tokenized_dataset(train_rows, tokenizer, cfg.max_seq_length)
    valid_ds = _build_tokenized_dataset(valid_rows, tokenizer, cfg.max_seq_length)

    collator = DataCollatorForLanguageModeling(tokenizer=tokenizer, mlm=False)

    args = TrainingArguments(
        output_dir=str(cfg.output_dir),
        num_train_epochs=cfg.epochs,
        learning_rate=cfg.learning_rate,
        per_device_train_batch_size=cfg.batch_size,
        per_device_eval_batch_size=max(1, cfg.batch_size),
        gradient_accumulation_steps=cfg.grad_accum_steps,
        logging_steps=cfg.logging_steps,
        eval_strategy="steps",
        eval_steps=cfg.eval_steps,
        save_steps=cfg.save_steps,
        save_total_limit=3,
        fp16=torch.cuda.is_available(),
        bf16=False,
        report_to="none",
        gradient_checkpointing=True,
        remove_unused_columns=False,
        seed=cfg.seed,
    )

    trainer = Trainer(
        model=model,
        args=args,
        train_dataset=train_ds,
        eval_dataset=valid_ds,
        data_collator=collator,
    )

    train_result = trainer.train()
    trainer.save_model()
    tokenizer.save_pretrained(cfg.output_dir)

    metrics = train_result.metrics
    metrics["train_records"] = len(train_ds)
    metrics["valid_records"] = len(valid_ds)
    metrics["quantized_4bit"] = quantized
    metrics["base_model"] = cfg.base_model
    metrics["output_dir"] = str(cfg.output_dir)
    return metrics


def main() -> None:
    parser = argparse.ArgumentParser(description="LoRA fine-tuning for Auto Forensics model prompts.")
    parser.add_argument("--base-model", default="google/gemma-3-4b-it", help="HF base model id.")
    parser.add_argument(
        "--train-file",
        type=Path,
        default=Path("training") / "data" / "train.jsonl",
        help="Training JSONL file from dataset generator.",
    )
    parser.add_argument(
        "--valid-file",
        type=Path,
        default=Path("training") / "data" / "valid.jsonl",
        help="Validation JSONL file from dataset generator.",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("training") / "outputs" / "auto-forensics-gemma3-lora",
        help="Output directory for LoRA adapter.",
    )
    parser.add_argument("--epochs", type=float, default=2.0)
    parser.add_argument("--learning-rate", type=float, default=2e-4)
    parser.add_argument("--batch-size", type=int, default=1)
    parser.add_argument("--grad-accum-steps", type=int, default=16)
    parser.add_argument("--max-seq-length", type=int, default=1024)
    parser.add_argument("--logging-steps", type=int, default=10)
    parser.add_argument("--eval-steps", type=int, default=60)
    parser.add_argument("--save-steps", type=int, default=60)
    parser.add_argument("--lora-r", type=int, default=16)
    parser.add_argument("--lora-alpha", type=int, default=32)
    parser.add_argument("--lora-dropout", type=float, default=0.05)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument(
        "--no-4bit",
        action="store_true",
        help="Disable 4-bit quantized loading (requires much more VRAM).",
    )
    args = parser.parse_args()

    if not args.train_file.exists():
        raise SystemExit(f"Training file not found: {args.train_file}")
    if not args.valid_file.exists():
        raise SystemExit(f"Validation file not found: {args.valid_file}")

    cfg = TrainConfig(
        base_model=args.base_model,
        train_file=args.train_file,
        valid_file=args.valid_file,
        output_dir=args.output_dir,
        epochs=args.epochs,
        learning_rate=args.learning_rate,
        batch_size=args.batch_size,
        grad_accum_steps=args.grad_accum_steps,
        max_seq_length=args.max_seq_length,
        logging_steps=args.logging_steps,
        eval_steps=args.eval_steps,
        save_steps=args.save_steps,
        lora_r=args.lora_r,
        lora_alpha=args.lora_alpha,
        lora_dropout=args.lora_dropout,
        use_4bit=not args.no_4bit,
        seed=args.seed,
    )

    cfg.output_dir.mkdir(parents=True, exist_ok=True)
    os.environ.setdefault("TOKENIZERS_PARALLELISM", "false")

    metrics = _train(cfg)
    metrics_path = cfg.output_dir / "train_metrics.json"
    metrics_path.write_text(json.dumps(metrics, indent=2), encoding="utf-8")
    print(json.dumps(metrics, indent=2))


if __name__ == "__main__":
    main()
