# Fine-tuning (LoRA) without test-set leakage

**Goal:** test whether fine-tuning improves vulnerability detection and repair. The fine-tuned model is compared with its own base model on the same Vul4C cases.

**Rule:** Vul4C is the test set and is never used for training. Training data comes from another dataset, and everything that overlaps with Vul4C is removed first.

```text
PrimeVul / MegaVul pairs ──► training/build_finetune_dataset.py ──► data/finetune/{train,valid}.jsonl + manifest.json
                              (Vul4C overlap removed)                     │
                                                                          ▼
                                                   training/train_lora.py ──► checkpoints/<name>/ (LoRA adapter)
                                                                          │
                                         config/experiment.json "adapter" ▼
                                         pipeline/run_experiment.py (same prompts, same cases)
```

## 1. Get the training data

The recommended source is **PrimeVul (paired)**: about 5,480 vulnerable/fixed function pairs in C/C++, with CWE and CVE labels. The paired files are `primevul_train_paired.jsonl` and `primevul_valid_paired.jsonl`. Download them from the PrimeVul GitHub repository (DLVulDet/PrimeVul), which links to the data, or from a Hugging Face mirror.

MegaVul, or any JSONL with `func_before` / `func_after` records, also works. The loader recognises common field names (`commit_id`/`commit_hash`, `project`/`repo_name`, `cve`/`cve_id`, `cwe`/`cwe_ids`, ...). Unrecognised records are counted in the manifest, so check it after the first run.

## 2. Build the dataset (removes Vul4C overlap)

```bash
python3 training/build_finetune_dataset.py \
    --input primevul_train_paired.jsonl primevul_valid_paired.jsonl \
    --vul4c-root /path/to/SoK/Vul4C-Benchmark \
    --out data/finetune
```

A training pair is removed when any of the following holds:

| Reason (in `manifest.json`) | Check |
|---|---|
| `removed_leak_cve` | Same CVE ID as a Vul4C case |
| `removed_leak_commit` | Commit hash appears in Vul4C metadata |
| `removed_leak_project` | Same project as a Vul4C case (libtiff, jasper, binutils, ...); on by default |
| `removed_leak_identical_code` | Vulnerable or fixed function identical to a Vul4C region (ignoring whitespace and comments) |
| `removed_too_long` | Function longer than 300 lines (the evaluation's region limit) |
| `removed_no_code_change`, `removed_duplicate_pair` | Data cleaning |

Each pair becomes three examples, and their prompts come from the **same functions the evaluation uses** (`pipeline/task_prompts.py`):

- detection on the vulnerable version, with answer `{"is_vulnerable": true, "cwe": ...}`;
- detection on the fixed version, with answer `{"is_vulnerable": false, ...}`;
- repair, with the fixed function as the answer.

The validation split is grouped by commit. Report the numbers in `manifest.json` in the paper.

## 3. Train

```bash
# Qwen2.5-Coder-1.5B on a 6 GB GPU
python3 training/train_lora.py --model Qwen/Qwen2.5-Coder-1.5B-Instruct \
    --data data/finetune --output checkpoints/qwen1.5b-lora --gradient-checkpointing

# Qwen2.5-Coder-7B: QLoRA on a 16 GB GPU (free Colab or Kaggle T4)
pip install bitsandbytes
python3 training/train_lora.py --model Qwen/Qwen2.5-Coder-7B-Instruct --qlora \
    --data data/finetune --output checkpoints/qwen7b-qlora --gradient-checkpointing
```

Run with `--dry-run` first. It reports token lengths and how many examples fit within `--max-length` (default 3072); longer examples are skipped, not truncated. For a quick first run, add `--max-train-examples 2000`.

The defaults are LoRA r=16, alpha=32, dropout 0.05 on all attention and MLP projections, learning rate 2e-4 with a cosine schedule, 2 epochs, and an effective batch size of 16. The loss is computed on the answer tokens only. `checkpoints/<name>/training_run.json` records the settings, losses, library versions, the SHA-256 of the data files, and the leakage manifest.

## 4. Evaluate the fine-tuned model

Add an entry to `config/experiment.json`, keeping the same `experiment_name` and `cases` as the base model's run:

```json
{ "name": "qwen1.5b-lora", "provider": "hf_local", "enabled": true,
  "model": "Qwen/Qwen2.5-Coder-1.5B-Instruct", "adapter": "checkpoints/qwen1.5b-lora",
  "torch_dtype": "float16" }
```

Also run the **base** model through `hf_local` (the same entry without `adapter`). Ollama uses its own quantised weights, so comparing an Ollama base model with an `hf_local` fine-tuned model would mix two variables. Then run:

```bash
python3 pipeline/run_experiment.py --config config/experiment.json --stage all \
    --models qwen2.5-coder-1.5b qwen1.5b-lora
```

The report's McNemar table tests whether the difference between base and fine-tuned is significant.

To run the fine-tuned model in Ollama instead, train with `--merge`, convert `checkpoints/<name>/merged` to GGUF with llama.cpp, and import it with a Modelfile. The `hf_local` route is simpler and avoids an extra quantisation step.

## Caveats to state in the paper

- PrimeVul labels are automatic. The authors report 86–92% correctness in a manual check, so some training labels are wrong.
- The benign reasoning text in training answers is a fixed sentence, and the vulnerable reasoning text is the CVE description. Only `is_vulnerable` and `cwe` are scored, so this does not affect the metrics.
- Excluding Vul4C projects also removes useful in-domain examples. That is deliberate. `--keep-test-projects` disables this filter (the CVE, commit and identical-code checks still apply), but report it if you use it.
