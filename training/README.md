# Local LLM Fine-Tuning for Auto Forensics

The JSONL files in `training/data/` are synthetic prompts generated from the scripts in this folder. They are not case evidence, and they are not required to install or run the tool. The offline demo uses `--llm mock` and does not train a model.

This folder contains a full local workflow to fine-tune an instruction model for the JSON prompts used by:

- `src/auto_forensics/llama_workflow.py`

The pipeline builds synthetic supervision data from repo artifacts, trains a LoRA adapter, and evaluates strict JSON compliance.

## 1) Environment

Recommended: Linux/WSL2 with CUDA for QLoRA training.

Windows PowerShell example with explicit Python path:

```powershell
"C:\Users\Benji\AppData\Local\Programs\Python\Python312\python.exe" -m venv training\.venv
training\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r training\requirements-train.txt
```

## 2) Generate Synthetic Dataset

```powershell
python training\generate_synthetic_dataset.py --scenario-count 260
```

Outputs:

- `training/data/train.jsonl`
- `training/data/valid.jsonl`
- `training/data/manifest.json`

## 3) Train LoRA Adapter

Gemma 3 4B target (recommended for RTX 4060 8GB with 4-bit loading):

```powershell
python training\train_lora.py `
  --base-model google/gemma-3-4b-it `
  --train-file training\data\train.jsonl `
  --valid-file training\data\valid.jsonl `
  --output-dir training\outputs\auto-forensics-gemma3-lora `
  --epochs 2 `
  --batch-size 1 `
  --grad-accum-steps 16 `
  --max-seq-length 1024
```

If your HF token is required for Gemma access, authenticate before training.

## 4) Evaluate JSON Compliance

```powershell
python training\evaluate_lora.py `
  --base-model google/gemma-3-4b-it `
  --adapter-dir training\outputs\auto-forensics-gemma3-lora `
  --eval-file training\data\valid.jsonl `
  --samples 60
```

Target quality for app reliability:

- `json_parse_rate >= 0.95`
- `schema_coverage_rate >= 0.90`
- `numeric_range_rate >= 0.90`

## 5) Merge Adapter

```powershell
python training\merge_lora.py `
  --base-model google/gemma-3-4b-it `
  --adapter-dir training\outputs\auto-forensics-gemma3-lora `
  --output-dir training\outputs\merged-gemma3-auto-forensics
```

## 6) Serve and Connect to Auto Forensics

You have two options:

1. OpenAI-compatible server from the merged HF model (vLLM/TGI/local service).
2. Convert merged model to GGUF and import into LM Studio.

For LM Studio conversion you need `llama.cpp` conversion + quantization tools. After import and load, point the app at LM Studio:

```powershell
$env:AUTO_FORENSICS_OPENAI_ENDPOINT="http://127.0.0.1:1234"
$env:AUTO_FORENSICS_LLAMA_MODEL="<loaded-model-identifier>"
```

Then run normal case analysis:

```powershell
auto-forensics analyze --case-id case-2026-001
```

## Notes

- The current local LM Studio GGUF files are inference artifacts, not directly trainable weights.
- Fine-tuning happens against an HF base model; export/conversion is required if you want LM Studio hosting.
