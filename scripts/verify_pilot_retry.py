#!/usr/bin/env python3
"""
Verification script for fresh retry configuration (config/pilot_retry.json).
Verifies that:
1. config/pilot_retry.json differs from config/pilot.json ONLY in experiment_name.
2. results/docker_pilot_retry/generations.jsonl is identical to results/docker_pilot/generations.jsonl.
3. Pipeline effective input/output paths resolve cleanly.
"""

import hashlib
import json
import sys
from pathlib import Path

REPO_ROOT = Path("/mnt/c/Users/Rohit Kumawat/Research/llm-vul4c-research")
CONFIG_PILOT = REPO_ROOT / "config/pilot.json"
CONFIG_RETRY = REPO_ROOT / "config/pilot_retry.json"
ORIG_GENS = REPO_ROOT / "results/docker_pilot/generations.jsonl"
RETRY_DIR = REPO_ROOT / "results/docker_pilot_retry"
RETRY_GENS = RETRY_DIR / "generations.jsonl"


def main() -> int:
    print("=" * 70)
    print("PILOT RETRY CONFIGURATION VERIFICATION")
    print("=" * 70)

    # 1. Config diff check
    with open(CONFIG_PILOT, "r", encoding="utf-8") as f:
        pilot_cfg = json.load(f)
    with open(CONFIG_RETRY, "r", encoding="utf-8") as f:
        retry_cfg = json.load(f)

    diffs = []
    for k in set(list(pilot_cfg.keys()) + list(retry_cfg.keys())):
        if pilot_cfg.get(k) != retry_cfg.get(k):
            diffs.append((k, pilot_cfg.get(k), retry_cfg.get(k)))

    print("\n--- 1. Configuration Diff Check ---")
    print(f"Total key differences: {len(diffs)}")
    for k, v_orig, v_retry in diffs:
        print(f"  Field '{k}':")
        print(f"    config/pilot.json:       {v_orig}")
        print(f"    config/pilot_retry.json: {v_retry}")

    assert len(diffs) == 1 and diffs[0][0] == "experiment_name", \
        f"Unexpected differences between configs: {diffs}"
    assert retry_cfg["experiment_name"] == "docker_pilot_retry", \
        f"Expected experiment_name 'docker_pilot_retry', got '{retry_cfg['experiment_name']}'"
    print("  [PASS] config/pilot_retry.json differs from config/pilot.json ONLY in experiment_name.")

    # 2. Generations integrity check
    print("\n--- 2. Staged Generations Check ---")
    sha_orig = hashlib.sha256(open(ORIG_GENS, "rb").read()).hexdigest()
    sha_retry = hashlib.sha256(open(RETRY_GENS, "rb").read()).hexdigest()

    count_orig = len(open(ORIG_GENS, "r", encoding="utf-8").readlines())
    count_retry = len(open(RETRY_GENS, "r", encoding="utf-8").readlines())

    print(f"  Original generations count: {count_orig} (SHA256: {sha_orig})")
    print(f"  Retry generations count:    {count_retry} (SHA256: {sha_retry})")

    assert count_retry == 60, f"Expected 60 records, found {count_retry}"
    assert sha_orig == sha_retry, "SHA256 checksum mismatch between original and retry generations!"
    print("  [PASS] Staged generations are identical byte-for-byte (60 records, verified hash).")

    # 3. Pipeline path resolution
    print("\n--- 3. Pipeline Effective Path Resolution ---")
    out_dir = Path(retry_cfg["output_dir"]) / retry_cfg["experiment_name"]
    abs_out_dir = REPO_ROOT / out_dir
    print(f"  Working repository root:       {REPO_ROOT}")
    print(f"  Target output directory:       {out_dir}  (absolute: {abs_out_dir})")
    print(f"  Effective input generations:   {out_dir / 'generations.jsonl'}")
    print(f"  Effective output calibration:  {out_dir / 'calibration.jsonl'}")
    print(f"  Effective output evaluations:  {out_dir / 'evaluations.jsonl'}")
    print(f"  Effective output report:       {out_dir / 'report.md'}")
    print(f"  Effective output cases:        {out_dir / 'cases.json'}")
    print(f"  Effective output config_used:  {out_dir / 'config_used.json'}")

    assert (abs_out_dir / "generations.jsonl").exists(), "Target generations.jsonl not found at resolved path!"
    print("  [PASS] Pipeline will read from and write to the correct resolved paths.")

    print("\n" + "=" * 70)
    print("ALL RETRY VERIFICATION CHECKS PASSED")
    print("=" * 70)
    return 0


if __name__ == "__main__":
    sys.exit(main())
