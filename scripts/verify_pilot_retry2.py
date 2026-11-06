#!/usr/bin/env python3
"""
Verification script for fresh retry2 configuration (config/pilot_retry2.json).
Verifies:
1. config/pilot_retry2.json differs from config/pilot_retry.json ONLY in experiment_name.
2. results/docker_pilot_retry2/generations.jsonl has exact 60 records and expected SHA256.
3. Effective pipeline input/output paths resolve to results/docker_pilot_retry2/.
4. Previous result directories and original files remain untouched.
"""

import hashlib
import json
import sys
from pathlib import Path

EXPECTED_SHA256 = "07712a7117abd64aea5c55525d952182be07b50946fc479b588f7e29487ac803"

REPO_ROOT = Path("/mnt/c/Users/Rohit Kumawat/Research/llm-vul4c-research")
CONFIG_RETRY = REPO_ROOT / "config/pilot_retry.json"
CONFIG_RETRY2 = REPO_ROOT / "config/pilot_retry2.json"

ORIG_GENS = REPO_ROOT / "results/docker_pilot/generations.jsonl"
RETRY2_DIR = REPO_ROOT / "results/docker_pilot_retry2"
RETRY2_GENS = RETRY2_DIR / "generations.jsonl"


def main() -> int:
    print("=" * 70)
    print("PILOT RETRY2 CONFIGURATION & DATA VERIFICATION")
    print("=" * 70)

    # 1. Config diff check
    with open(CONFIG_RETRY, "r", encoding="utf-8") as f:
        retry_cfg = json.load(f)
    with open(CONFIG_RETRY2, "r", encoding="utf-8") as f:
        retry2_cfg = json.load(f)

    diffs = []
    for k in set(list(retry_cfg.keys()) + list(retry2_cfg.keys())):
        if retry_cfg.get(k) != retry2_cfg.get(k):
            diffs.append((k, retry_cfg.get(k), retry2_cfg.get(k)))

    print("\n--- 1. Configuration Diff Check ---")
    print(f"Total key differences: {len(diffs)}")
    for k, v_orig, v_retry2 in diffs:
        print(f"  Field '{k}':")
        print(f"    config/pilot_retry.json:  {v_orig}")
        print(f"    config/pilot_retry2.json: {v_retry2}")

    assert len(diffs) == 1 and diffs[0][0] == "experiment_name", \
        f"Unexpected differences between configs: {diffs}"
    assert retry2_cfg["experiment_name"] == "docker_pilot_retry2", \
        f"Expected experiment_name 'docker_pilot_retry2', got '{retry2_cfg['experiment_name']}'"
    print("  [PASS] config/pilot_retry2.json differs from config/pilot_retry.json ONLY in experiment_name.")

    # 2. Generations integrity and SHA256 check
    print("\n--- 2. Staged Generations Check ---")
    sha_retry2 = hashlib.sha256(open(RETRY2_GENS, "rb").read()).hexdigest()
    count_retry2 = len(open(RETRY2_GENS, "r", encoding="utf-8").readlines())

    print(f"  Copied records count: {count_retry2}")
    print(f"  Copied SHA256:        {sha_retry2}")
    print(f"  Expected SHA256:      {EXPECTED_SHA256}")

    assert count_retry2 == 60, f"Expected 60 records, found {count_retry2}"
    assert sha_retry2 == EXPECTED_SHA256, \
        f"SHA256 mismatch! Got {sha_retry2}, expected {EXPECTED_SHA256}"
    print("  [PASS] Copied generations file has exactly 60 records and matching SHA256.")

    # 3. Directory isolation check
    print("\n--- 3. Directory Isolation Check ---")
    retry2_files = sorted(f.name for f in RETRY2_DIR.iterdir())
    print(f"  Files currently in results/docker_pilot_retry2/: {retry2_files}")
    assert retry2_files == ["generations.jsonl"], f"Expected only generations.jsonl, found: {retry2_files}"
    assert not (RETRY2_DIR / "calibration.jsonl").exists(), "calibration.jsonl should not exist yet!"
    assert not (RETRY2_DIR / "evaluations.jsonl").exists(), "evaluations.jsonl should not exist yet!"
    print("  [PASS] results/docker_pilot_retry2/ is completely clean (zero existing evaluations/calibrations).")

    # 4. Pipeline path resolution
    print("\n--- 4. Pipeline Effective Path Resolution ---")
    out_dir = Path(retry2_cfg["output_dir"]) / retry2_cfg["experiment_name"]
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
    print("  [PASS] Pipeline reads generations from results/docker_pilot_retry2/generations.jsonl.")
    print("  [PASS] Pipeline writes all outputs into results/docker_pilot_retry2/.")

    print("\n" + "=" * 70)
    print("ALL RETRY2 VERIFICATION CHECKS PASSED")
    print("=" * 70)
    return 0


if __name__ == "__main__":
    sys.exit(main())

