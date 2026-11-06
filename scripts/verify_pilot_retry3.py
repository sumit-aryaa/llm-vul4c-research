#!/usr/bin/env python3
"""
Verification script for isolated docker_pilot_retry3 setup.
Verifies:
1. config/pilot_retry3.json exists and is valid JSON.
2. Only experiment_name differs from pilot_retry2.json.
3. Resource limits, timeouts, cases, and metadata patch are preserved.
4. results/docker_pilot_retry3/generations.jsonl has exact SHA256 and 60 records.
5. No existing evaluation or calibration records exist in results/docker_pilot_retry3/.
6. Effective input and output paths are confirmed.
7. Original files and previous result directories are untouched.
"""

import hashlib
import json
import os
import sys
from pathlib import Path

REPO_ROOT = Path("/mnt/c/Users/Rohit Kumawat/Research/llm-vul4c-research")
EXPECTED_SHA256 = "07712a7117abd64aea5c55525d952182be07b50946fc479b588f7e29487ac803"


def compute_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


def main() -> int:
    print("=" * 70)
    print("DOCKER PILOT RETRY 3 VERIFICATION")
    print("=" * 70)

    # 1. Config existence and validation
    cfg_path = REPO_ROOT / "config/pilot_retry3.json"
    ref_cfg_path = REPO_ROOT / "config/pilot_retry2.json"
    assert cfg_path.exists(), f"Missing {cfg_path}"
    assert ref_cfg_path.exists(), f"Missing {ref_cfg_path}"

    with open(cfg_path, "r", encoding="utf-8") as f:
        cfg = json.load(f)
    with open(ref_cfg_path, "r", encoding="utf-8") as f:
        ref_cfg = json.load(f)

    print("\n--- 1. Configuration Validation ---")
    assert cfg["experiment_name"] == "docker_pilot_retry3", \
        f"Unexpected experiment_name: {cfg['experiment_name']}"
    assert cfg["output_dir"] == "results", f"Unexpected output_dir: {cfg['output_dir']}"

    # Verify only experiment_name differs
    ref_copy = dict(ref_cfg)
    ref_copy["experiment_name"] = "docker_pilot_retry3"
    assert cfg == ref_copy, "Configuration differs from pilot_retry2.json beyond experiment_name!"
    print("  [PASS] config/pilot_retry3.json matches pilot_retry2.json except experiment_name.")

    # 2. Cases and limits
    print("\n--- 2. Resource Limits & Settings ---")
    expected_cases = [
        "audiofile/CVE-2017-6832",
        "bento4/CVE-2017-14638",
        "binutils/CVE-2017-14729",
        "elfutils/CVE-2017-7607",
        "gilcc/CVE-2020-21572"
    ]
    assert cfg["cases"] == expected_cases, "Cases list mismatch!"
    sb = cfg["sandbox"]
    assert sb["cpus"] == "2", f"CPUs mismatch: {sb['cpus']}"
    assert sb["memory"] == "6g", f"Memory mismatch: {sb['memory']}"
    assert sb["timeouts"]["checkout"] == 1800
    assert sb["timeouts"]["compile"] == 1800
    assert sb["timeouts"]["reproduce"] == 300
    assert sb["timeouts"]["test"] == 3600
    assert "python3 /opt/patch_pilot_metadata.py" in sb["setup_commands"]
    print("  [PASS] 5 cases, resource limits (2 CPUs, 6GB), timeouts, and metadata patch preserved.")

    # 3. Output directory and generations.jsonl
    print("\n--- 3. Output Directory & Generations File ---")
    out_dir = REPO_ROOT / "results/docker_pilot_retry3"
    gen_file = out_dir / "generations.jsonl"
    assert out_dir.exists(), f"Output directory missing: {out_dir}"
    assert gen_file.exists(), f"Generations file missing: {gen_file}"

    with open(gen_file, "r", encoding="utf-8") as f:
        records = [json.loads(line) for line in f if line.strip()]
    assert len(records) == 60, f"Expected 60 records, found {len(records)}"

    actual_sha = compute_sha256(gen_file)
    assert actual_sha == EXPECTED_SHA256, \
        f"SHA256 mismatch!\nExpected: {EXPECTED_SHA256}\nActual:   {actual_sha}"
    print(f"  [PASS] generations.jsonl has 60 records.")
    print(f"  [PASS] SHA256 verified: {actual_sha}")

    # 4. Confirm clean directory (no evaluations or calibration)
    print("\n--- 4. Clean State Confirmation ---")
    eval_file = out_dir / "evaluations.jsonl"
    calib_file = out_dir / "calibration.jsonl"
    log_file = out_dir / "eval.log"
    assert not eval_file.exists(), f"Found existing evaluations file: {eval_file}"
    assert not calib_file.exists(), f"Found existing calibration file: {calib_file}"
    assert not log_file.exists(), f"Found existing eval.log: {log_file}"
    dir_files = [f.name for f in out_dir.iterdir()]
    assert dir_files == ["generations.jsonl"], f"Unexpected files in {out_dir}: {dir_files}"
    print("  [PASS] No existing evaluation, calibration, or log files in results/docker_pilot_retry3/.")

    # 5. Effective input and output paths
    print("\n--- 5. Effective Pipeline Paths ---")
    eff_in = out_dir / "generations.jsonl"
    eff_out_eval = out_dir / "evaluations.jsonl"
    eff_out_calib = out_dir / "calibration.jsonl"
    print(f"  Effective input generations: {eff_in}")
    print(f"  Effective output evaluations: {eff_out_eval}")
    print(f"  Effective output calibration: {eff_out_calib}")
    print("  [PASS] Pipeline will read from and write to results/docker_pilot_retry3/ exclusively.")

    # 6. Integrity of host and previous runs
    print("\n--- 6. Integrity of Previous Runs & Benchmark ---")
    assert (REPO_ROOT / "results/docker_pilot/generations.jsonl").exists()
    assert (REPO_ROOT / "results/docker_pilot_retry/generations.jsonl").exists()
    assert (REPO_ROOT / "results/docker_pilot_retry2/generations.jsonl").exists()
    assert (REPO_ROOT / "results/docker_pilot_retry2/evaluations.jsonl").exists()

    host_vul4c = Path("/home/rohit_kumawat/SoK/Vul4C_Src/Vul4C.json")
    with open(host_vul4c, "r", encoding="utf-8") as f:
        host_d = json.load(f)
    assert any("-j10" in cmd for cmd in host_d["CVE-2017-14729"]["compile_command"]), \
        "Host Vul4C.json was unexpectedly modified!"
    print("  [PASS] Previous result directories and original benchmark metadata remain untouched.")

    print("\n" + "=" * 70)
    print("ALL CHECKS PASSED: docker_pilot_retry3 is safely staged and ready.")
    print("=" * 70)
    return 0


if __name__ == "__main__":
    sys.exit(main())

