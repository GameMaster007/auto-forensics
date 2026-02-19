from __future__ import annotations

import argparse
from pathlib import Path

import torch
from peft import PeftModel
from transformers import AutoModelForCausalLM, AutoTokenizer


def main() -> None:
    parser = argparse.ArgumentParser(description="Merge LoRA adapter into a standalone HF model.")
    parser.add_argument("--base-model", required=True, help="HF base model id.")
    parser.add_argument("--adapter-dir", type=Path, required=True, help="Path to trained adapter directory.")
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("training") / "outputs" / "merged-model",
        help="Directory to write merged model.",
    )
    args = parser.parse_args()

    dtype = torch.float16 if torch.cuda.is_available() else torch.float32
    tokenizer = AutoTokenizer.from_pretrained(args.base_model, use_fast=True)
    base = AutoModelForCausalLM.from_pretrained(
        args.base_model,
        torch_dtype=dtype,
        device_map="auto" if torch.cuda.is_available() else None,
    )
    model = PeftModel.from_pretrained(base, str(args.adapter_dir))
    merged = model.merge_and_unload()

    args.output_dir.mkdir(parents=True, exist_ok=True)
    merged.save_pretrained(args.output_dir)
    tokenizer.save_pretrained(args.output_dir)
    print(f"Merged model written to: {args.output_dir}")


if __name__ == "__main__":
    main()
