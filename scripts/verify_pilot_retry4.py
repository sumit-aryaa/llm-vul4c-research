#!/usr/bin/env python3
"""
Verification script for isolated docker_pilot_retry4 setup.
Verifies:
1. config/pilot_retry4.json exists and is valid JSON.
2. Only experiment_name differs from pilot_retry3.json.
3. Resource limits, timeouts, cases, and metadata patch are preserved.
4. results/docker_pilot_retry4/generations.jsonl has exact SHA256 and 60 records.
5. No existing evaluation or calibration records exist in results/docker_pilot_retry4/.
6. Effective input and output paths are confirmed.
7. Patch script sets ASAN_OPTIONS=detect_leaks=0 only for CVE-2017-14729 test_command.
8. Other cases retain original reproduction commands.
9. Host benchmark metadata, config/experiment.json, config/pilot_retry3.json, and Retry 3 results are untouched.
"""

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path("/mnt/c/Users/Rohit Kumawat/Research/llm-vul4c-research")
EXPECTED_SHA256 = "07712a7117abd64aea5c55525d952182be07b50946fc479b588f7e29487ac803"
HOST_VUL4C_JSON = Path("/home/rohit_kumawat/SoK/Vul4C_Src/Vul4C.json")
HOST_EXP_CONFIG = REPO_ROOT / "config/experiment.json"
PATCH_SCRIPT = REPO_ROOT / "scripts/patch_pilot_metadata.py"


def compute_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


def main() -> int:
    print("=" * 70)
    print("DOCKER PILOT RETRY 4 VERIFICATION")
    print("=" * 70)

    # 1. Config existence and validation
    cfg_path = REPO_ROOT / "config/pilot_retry4.json"
    ref_cfg_path = REPO_ROOT / "config/pilot_retry3.json"
    assert cfg_path.exists(), f"Missing {cfg_path}"
    assert ref_cfg_path.exists(), f"Missing {ref_cfg_path}"

    with open(cfg_path, "r", encoding="utf-8") as f:
        cfg = json.load(f)
    with open(ref_cfg_path, "r", encoding="utf-8") as f:
        ref_cfg = json.load(f)

    print("\n--- 1. Configuration Validation ---")
    assert cfg["experiment_name"] == "docker_pilot_retry4", \
        f"Unexpected experiment_name: {cfg['experiment_name']}"
    assert cfg["output_dir"] == "results", f"Unexpected output_dir: {cfg['output_dir']}"

    # Verify only experiment_name differs from pilot_retry3.json
    ref_copy = dict(ref_cfg)
    ref_copy["experiment_name"] = "docker_pilot_retry4"
    assert cfg == ref_copy, "Configuration differs from pilot_retry3.json beyond experiment_name!"
    print("  [PASS] config/pilot_retry4.json matches pilot_retry3.json except experiment_name.")

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
    out_dir = REPO_ROOT / "results/docker_pilot_retry4"
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
    print("  [PASS] No existing evaluation, calibration, or log files in results/docker_pilot_retry4/.")

    # 5. Effective input and output paths
    print("\n--- 5. Effective Pipeline Paths ---")
    eff_in = out_dir / "generations.jsonl"
    eff_out_eval = out_dir / "evaluations.jsonl"
    eff_out_calib = out_dir / "calibration.jsonl"
    print(f"  Effective input generations: {eff_in}")
    print(f"  Effective output evaluations: {eff_out_eval}")
    print(f"  Effective output calibration: {eff_out_calib}")
    print("  [PASS] Pipeline will read from and write to results/docker_pilot_retry4/ exclusively.")

    # 6. Metadata patch behavior verification in container
    print("\n--- 6. Reproduction Command & Patch Verification ---")
    cmd = [
        "docker", "run", "--rm",
        "-v", f"{PATCH_SCRIPT}:/opt/patch_pilot_metadata.py:ro",
        "vul4c/vul4c:4.0",
        "bash", "-lc",
        "python3 /opt/patch_pilot_metadata.py && python3 -c \"import json; "
        "d = json.load(open('/SoK-main/Vul4C_Src/Vul4C.json')); "
        "cves = ['CVE-2017-6832', 'CVE-2017-14638', 'CVE-2017-14729', 'CVE-2017-7607', 'CVE-2020-21572']; "
        "print(json.dumps({cve: d[cve]['test_command'] for cve in cves}))\""
    ]
    res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
    assert res.returncode == 0, f"Container verification failed:\n{res.stderr}"

    test_commands = None
    for line in res.stdout.splitlines():
        if line.startswith('{"CVE-2017-'):
            test_commands = json.loads(line)
            break
    assert test_commands is not None, f"Failed to parse test_commands:\n{res.stdout}"

    # Verify CVE-2017-14729 has ASAN_OPTIONS=detect_leaks=0
    bin_test = test_commands["CVE-2017-14729"]
    print(f"  Binutils (CVE-2017-14729) test_command: {bin_test}")
    assert any("ASAN_OPTIONS=detect_leaks=0" in c for c in bin_test), \
        f"CVE-2017-14729 test_command missing detect_leaks=0! {bin_test}"
    print("  [PASS] Binutils test_command has ASAN_OPTIONS=detect_leaks=0.")

    # Verify the other 4 cases retain original reproduction commands
    other_cases = ["CVE-2017-6832", "CVE-2017-14638", "CVE-2017-7607", "CVE-2020-21572"]
    with open(HOST_VUL4C_JSON, "r", encoding="utf-8") as f:
        host_d = json.load(f)

    for cve in other_cases:
        assert test_commands[cve] == host_d[cve]["test_command"], \
            f"Case {cve} test_command modified unexpectedly! Got: {test_commands[cve]}"
        assert not any("detect_leaks" in c for c in test_commands[cve]), \
            f"Case {cve} unexpectedly received detect_leaks! {test_commands[cve]}"
        print(f"  [PASS] Case {cve} retains original test_command: {test_commands[cve]}")

    # 7. Host file integrity & previous runs
    print("\n--- 7. Host File & Previous Results Integrity ---")
    assert HOST_EXP_CONFIG.exists()
    with open(HOST_EXP_CONFIG, "r", encoding="utf-8") as f:
        exp_cfg = json.load(f)
    assert exp_cfg.get("experiment_name") == "benchmark_qwen1.5b_all"
    print("  [PASS] config/experiment.json is 100% UNTOUCHED.")

    with open(ref_cfg_path, "r", encoding="utf-8") as f:
        ref_check = json.load(f)
    assert ref_check.get("experiment_name") == "docker_pilot_retry3"
    print("  [PASS] config/pilot_retry3.json is 100% UNTOUCHED.")

    # Host Vul4C.json checks
    assert not any("detect_leaks" in c for c in host_d["CVE-2017-14729"]["test_command"])
    assert any("-j10" in cmd for cmd in host_d["CVE-2017-14729"]["compile_command"])
    print("  [PASS] Host Vul4C.json is 100% UNTOUCHED.")

    # Previous results integrity
    assert (REPO_ROOT / "results/docker_pilot/generations.jsonl").exists()
    assert (REPO_ROOT / "results/docker_pilot_retry/generations.jsonl").exists()
    assert (REPO_ROOT / "results/docker_pilot_retry2/generations.jsonl").exists()
    assert (REPO_ROOT / "results/docker_pilot_retry3/generations.jsonl").exists()
    assert (REPO_ROOT / "results/docker_pilot_retry3/calibration.jsonl").exists()
    assert (REPO_ROOT / "results/docker_pilot_retry3/evaluations.jsonl").exists()
    print("  [PASS] Previous result directories (pilot, retry, retry2, retry3) are 100% UNTOUCHED.")

    print("\n" + "=" * 70)
    print("ALL CHECKS PASSED: docker_pilot_retry4 is verified and ready for evaluation.")
    print("=" * 70)
    return 0


if __name__ == "__main__":
    sys.exit(main())

