"""LoRA / QLoRA fine-tuning on the dataset from build_finetune_dataset.py.

The loss is computed on the assistant answer only (prompt tokens are masked),
using the model's own chat template, so training matches how the evaluation
pipeline prompts the model.

Examples:
  # Qwen2.5-Coder-1.5B on a 6 GB GPU (LoRA, fp16)
  python3 training/train_lora.py --model Qwen/Qwen2.5-Coder-1.5B-Instruct \\
      --data data/finetune --output checkpoints/qwen1.5b-lora --gradient-checkpointing

  # Qwen2.5-Coder-7B on a 16 GB GPU (e.g. free Colab/Kaggle T4): QLoRA, 4-bit base
  python3 training/train_lora.py --model Qwen/Qwen2.5-Coder-7B-Instruct --qlora \\
      --data data/finetune --output checkpoints/qwen7b-qlora --gradient-checkpointing

  # Check token lengths and how many examples fit, without training
  python3 training/train_lora.py --model Qwen/Qwen2.5-Coder-1.5B-Instruct --data data/finetune --dry-run

Then evaluate with the pipeline by adding to config/experiment.json:
  {"name": "qwen1.5b-lora", "provider": "hf_local", "model": "Qwen/Qwen2.5-Coder-1.5B-Instruct",
   "adapter": "checkpoints/qwen1.5b-lora", "enabled": true}

Requires: torch, transformers, peft (and bitsandbytes for --qlora).
"""

import argparse
from datetime import datetime, timezone
import hashlib
import json
import math
from pathlib import Path
import random
import sys
from typing import Any, Dict, List, Optional, Tuple

IGNORE_INDEX = -100


def load_examples(path: Path) -> List[Dict[str, Any]]:
    with open(path, "r", encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]


def encode_example(tokenizer: Any, messages: List[Dict[str, str]], max_length: int) -> Optional[Dict[str, List[int]]]:
    """Tokenize one chat example; labels cover only the assistant answer (+ end-of-turn).

    Returns None if the example does not fit in ``max_length`` (it is skipped, not
    truncated, because a truncated answer would teach incomplete outputs).
    """
    if not messages or messages[-1]["role"] != "assistant":
        raise ValueError("Each example must end with an assistant message")
    prompt_text = tokenizer.apply_chat_template(messages[:-1], tokenize=False, add_generation_prompt=True)
    full_text = tokenizer.apply_chat_template(messages, tokenize=False, add_generation_prompt=False)
    if not full_text.startswith(prompt_text):
        raise ValueError("Chat template does not render the prompt as a prefix of the full conversation")
    prompt_ids = tokenizer(prompt_text, add_special_tokens=False)["input_ids"]
    full_ids = tokenizer(full_text, add_special_tokens=False)["input_ids"]
    if full_ids[:len(prompt_ids)] != prompt_ids:
        # Token boundary shifted at the join; fall back to tokenizing the answer separately.
        answer_ids = tokenizer(full_text[len(prompt_text):], add_special_tokens=False)["input_ids"]
        full_ids = prompt_ids + answer_ids
    if len(full_ids) > max_length:
        return None
    labels = [IGNORE_INDEX] * len(prompt_ids) + full_ids[len(prompt_ids):]
    return {"input_ids": full_ids, "labels": labels}


def encode_all(tokenizer: Any, examples: List[Dict[str, Any]], max_length: int) -> Tuple[List[Dict[str, List[int]]], Dict[str, Any]]:
    encoded, lengths, skipped = [], [], 0
    by_task: Dict[str, int] = {}
    for ex in examples:
        enc = encode_example(tokenizer, ex["messages"], max_length)
        if enc is None:
            skipped += 1
            continue
        encoded.append(enc)
        lengths.append(len(enc["input_ids"]))
        task = ex.get("meta", {}).get("task", "unknown")
        by_task[task] = by_task.get(task, 0) + 1
    lengths.sort()
    stats = {
        "examples": len(examples), "kept": len(encoded), "skipped_too_long": skipped, "by_task": by_task,
        "tokens_median": lengths[len(lengths) // 2] if lengths else 0,
        "tokens_p95": lengths[int(len(lengths) * 0.95)] if lengths else 0,
        "tokens_max": lengths[-1] if lengths else 0,
        "supervised_tokens": sum(sum(1 for t in e["labels"] if t != IGNORE_INDEX) for e in encoded),
    }
    return encoded, stats


class PadCollator:
    def __init__(self, pad_id: int) -> None:
        self.pad_id = pad_id

    def __call__(self, batch: List[Dict[str, List[int]]]) -> Dict[str, Any]:
        import torch

        width = max(len(b["input_ids"]) for b in batch)
        ids, labels, mask = [], [], []
        for b in batch:
            pad = width - len(b["input_ids"])
            ids.append(b["input_ids"] + [self.pad_id] * pad)
            labels.append(b["labels"] + [IGNORE_INDEX] * pad)
            mask.append([1] * len(b["input_ids"]) + [0] * pad)
        return {"input_ids": torch.tensor(ids), "labels": torch.tensor(labels),
                "attention_mask": torch.tensor(mask)}


def _training_kwargs(cls: Any, kwargs: Dict[str, Any]) -> Dict[str, Any]:
    """Adapt argument names across transformers versions (v4 'evaluation_strategy' vs v5 'eval_strategy')."""
    import inspect

    params = inspect.signature(cls.__init__).parameters
    if "eval_strategy" not in params and "evaluation_strategy" in params:
        kwargs["evaluation_strategy"] = kwargs.pop("eval_strategy")
    return {k: v for k, v in kwargs.items() if k in params}


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest() if path.exists() else ""


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--model", required=True, help="Base model id or path")
    ap.add_argument("--data", default="data/finetune", help="Folder with train.jsonl / valid.jsonl")
    ap.add_argument("--output", default="checkpoints/lora")
    ap.add_argument("--qlora", action="store_true", help="Load the base model in 4-bit (needs bitsandbytes)")
    ap.add_argument("--epochs", type=float, default=2.0)
    ap.add_argument("--lr", type=float, default=2e-4)
    ap.add_argument("--batch-size", type=int, default=1)
    ap.add_argument("--grad-accum", type=int, default=16)
    ap.add_argument("--max-length", type=int, default=3072)
    ap.add_argument("--lora-r", type=int, default=16)
    ap.add_argument("--lora-alpha", type=int, default=32)
    ap.add_argument("--lora-dropout", type=float, default=0.05)
    ap.add_argument("--target-modules", nargs="+",
                    default=["q_proj", "k_proj", "v_proj", "o_proj", "gate_proj", "up_proj", "down_proj"])
    ap.add_argument("--max-train-examples", type=int)
    ap.add_argument("--gradient-checkpointing", action="store_true")
    ap.add_argument("--merge", action="store_true", help="Also save a merged full model (for Ollama/GGUF export)")
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--dry-run", action="store_true", help="Only tokenize and report lengths")
    args = ap.parse_args(argv)

    from transformers import AutoTokenizer

    data = Path(args.data)
    train_ex = load_examples(data / "train.jsonl")
    valid_ex = load_examples(data / "valid.jsonl") if (data / "valid.jsonl").exists() else []
    random.Random(args.seed).shuffle(train_ex)
    if args.max_train_examples:
        train_ex = train_ex[: args.max_train_examples]

    tokenizer = AutoTokenizer.from_pretrained(args.model)
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token
    train_enc, train_stats = encode_all(tokenizer, train_ex, args.max_length)
    valid_enc, valid_stats = encode_all(tokenizer, valid_ex, args.max_length)
    print("train:", json.dumps(train_stats))
    print("valid:", json.dumps(valid_stats))
    if args.dry_run:
        return 0
    if not train_enc:
        print("No training examples fit in --max-length.", file=sys.stderr)
        return 1

    import torch
    from peft import LoraConfig, get_peft_model, prepare_model_for_kbit_training
    from transformers import AutoModelForCausalLM, Trainer, TrainingArguments, set_seed

    set_seed(args.seed)
    bf16 = torch.cuda.is_available() and torch.cuda.is_bf16_supported()
    dtype = torch.bfloat16 if bf16 else torch.float16
    import transformers

    dtype_key = "dtype" if int(transformers.__version__.split(".")[0]) >= 5 else "torch_dtype"
    load_kwargs: Dict[str, Any] = {dtype_key: dtype}
    if torch.cuda.is_available():
        load_kwargs["device_map"] = "auto"
    if args.qlora:
        from transformers import BitsAndBytesConfig

        load_kwargs["quantization_config"] = BitsAndBytesConfig(
            load_in_4bit=True, bnb_4bit_quant_type="nf4", bnb_4bit_compute_dtype=dtype,
            bnb_4bit_use_double_quant=True)
    model = AutoModelForCausalLM.from_pretrained(args.model, **load_kwargs)
    model.config.use_cache = False
    if args.qlora:
        model = prepare_model_for_kbit_training(model, use_gradient_checkpointing=args.gradient_checkpointing)
    elif args.gradient_checkpointing:
        model.gradient_checkpointing_enable()
        model.enable_input_require_grads()
    model = get_peft_model(model, LoraConfig(
        r=args.lora_r, lora_alpha=args.lora_alpha, lora_dropout=args.lora_dropout,
        target_modules=args.target_modules, bias="none", task_type="CAUSAL_LM"))
    model.print_trainable_parameters()

    steps_per_epoch = math.ceil(len(train_enc) / (args.batch_size * args.grad_accum))
    total_steps = max(1, math.ceil(steps_per_epoch * args.epochs))
    targs = TrainingArguments(**_training_kwargs(TrainingArguments, dict(
        output_dir=args.output, num_train_epochs=args.epochs, learning_rate=args.lr,
        per_device_train_batch_size=args.batch_size, per_device_eval_batch_size=args.batch_size,
        gradient_accumulation_steps=args.grad_accum, lr_scheduler_type="cosine",
        warmup_steps=max(1, int(0.03 * total_steps)),
        logging_steps=max(1, steps_per_epoch // 20), save_strategy="epoch",
        eval_strategy="epoch" if valid_enc else "no", save_total_limit=2,
        bf16=bf16, fp16=not bf16 and torch.cuda.is_available(), report_to=[], seed=args.seed,
        gradient_checkpointing=args.gradient_checkpointing and not args.qlora,
        remove_unused_columns=False,
    )))
    trainer = Trainer(model=model, args=targs, train_dataset=train_enc, eval_dataset=valid_enc or None,
                      data_collator=PadCollator(tokenizer.pad_token_id))
    result = trainer.train()
    out = Path(args.output)
    model.save_pretrained(out)
    tokenizer.save_pretrained(out)

    meta = {
        "finished": datetime.now(timezone.utc).isoformat(),
        "base_model": args.model, "args": vars(args),
        "train_stats": train_stats, "valid_stats": valid_stats,
        "train_loss": result.training_loss,
        "eval": trainer.evaluate() if valid_enc else None,
        "data_sha256": {"train.jsonl": _sha256(data / "train.jsonl"), "valid.jsonl": _sha256(data / "valid.jsonl")},
        "data_manifest": json.loads((data / "manifest.json").read_text()) if (data / "manifest.json").exists() else None,
    }
    try:
        import peft
        import transformers
        meta["versions"] = {"torch": torch.__version__, "transformers": transformers.__version__, "peft": peft.__version__}
    except Exception:
        pass
    (out / "training_run.json").write_text(json.dumps(meta, indent=2, default=str), encoding="utf-8")

    if args.merge:
        if args.qlora:
            print("Note: merging onto a 4-bit base is lossy; reload the base in fp16 to merge for export.")
        merged = model.merge_and_unload()
        merged.save_pretrained(out / "merged")
        tokenizer.save_pretrained(out / "merged")
    print(f"Saved adapter to {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
