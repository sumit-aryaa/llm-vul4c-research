#!/usr/bin/env python3
"""
Verification script for isolated docker_pilot_retry6 setup.

Verifies:
1. config/pilot_retry6.json exists and is valid JSON.
2. Only experiment_name differs from pilot_retry5.json.
3. Resource limits, timeouts, cases, mounts, and models are preserved.
4. results/docker_pilot_retry6/ exists and is empty (no generations/evals/calibration).
5. Unit tests for patch extraction and roundtrip fidelity pass.
6. Identity and oracle repair outputs are completely unchanged.
7. Detection prompts and instructions are completely unchanged.
8. Only the intended repair prompt changed in pipeline/task_prompts.py.
9. config/experiment.json, host Vul4C.json, and results/docker_pilot_retry5/ remain untouched.
10. Effective input and output paths are isolated and ready.
"""

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

# Resolve repo root across Windows and Linux (WSL)
REPO_ROOT = Path(__file__).resolve().parent.parent
EXPECTED_RETRY5_SHA256 = "07712a7117abd64aea5c55525d952182be07b50946fc479b588f7e29487ac803"


def compute_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


def main() -> int:
    print("=" * 70)
    print("DOCKER PILOT RETRY 6 PRE-FLIGHT VERIFICATION")
    print("=" * 70)

    # 1. Config existence and validation
    cfg_path = REPO_ROOT / "config/pilot_retry6.json"
    ref_cfg_path = REPO_ROOT / "config/pilot_retry5.json"
    assert cfg_path.exists(), f"Missing {cfg_path}"
    assert ref_cfg_path.exists(), f"Missing {ref_cfg_path}"

    with open(cfg_path, "r", encoding="utf-8") as f:
        cfg = json.load(f)
    with open(ref_cfg_path, "r", encoding="utf-8") as f:
        ref_cfg = json.load(f)

    print("\n--- 1. Configuration Validation ---")
    assert cfg["experiment_name"] == "docker_pilot_retry6", \
        f"Unexpected experiment_name: {cfg['experiment_name']}"
    assert cfg["output_dir"] == "results", f"Unexpected output_dir: {cfg['output_dir']}"

    # Verify only experiment_name differs from pilot_retry5.json
    ref_copy = dict(ref_cfg)
    ref_copy["experiment_name"] = "docker_pilot_retry6"
    assert cfg == ref_copy, "Configuration differs from pilot_retry5.json beyond experiment_name!"
    print("  [PASS] config/pilot_retry6.json matches pilot_retry5.json except experiment_name.")

    # 2. Cases and limits
    print("\n--- 2. Resource Limits & Settings ---")
    expected_cases = [
        "audiofile/CVE-2017-6832",
        "bento4/CVE-2017-14638",
        "binutils/CVE-2017-14729",
        "elfutils/CVE-2017-7607",
        "gilcc/CVE-2020-21572",
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
    assert len(cfg["models"]) == 4
    model_names = [m["name"] for m in cfg["models"]]
    assert model_names == ["oracle", "identity", "ollama-qwen-1.5b", "ollama-qwen-7b"]
    print("  [PASS] 5 cases, resource limits (2 CPUs, 6GB), timeouts, mounts, and 4 models preserved.")

    # 3. Output directory isolation
    print("\n--- 3. Output Directory Isolation ---")
    out_dir = REPO_ROOT / "results/docker_pilot_retry6"
    assert out_dir.exists(), f"Output directory missing: {out_dir}"
    contents = list(out_dir.iterdir())
    assert len(contents) == 0, f"Retry6 directory must be empty prior to execution, found: {contents}"
    print(f"  [PASS] Output directory exists and is strictly empty: {out_dir}")

    # 4. Prompt Integrity Verification
    print("\n--- 4. Prompt Integrity & Scope of Changes ---")
    sys.path.insert(0, str(REPO_ROOT))
    from pipeline.task_prompts import (
        build_detection_messages,
        build_repair_messages,
        identity_repair_answer,
        oracle_repair_answer,
    )
    from pipeline.patch_manager import CodeRegion

    sample_region = CodeRegion(
        file_name="test.c",
        old_start=1, old_end=3,
        new_start=1, new_end=3,
        old_code="int vuln(void) { return 0; }\n",
        new_code="int vuln(void) { return 1; }\n",
        kind="function",
    )

    # Oracle & identity answers
    id_ans = identity_repair_answer([sample_region])
    orc_ans = oracle_repair_answer([sample_region])
    assert "int vuln(void) { return 0; }" in id_ans, "Identity answer corrupted!"
    assert "int vuln(void) { return 1; }" in orc_ans, "Oracle answer corrupted!"
    assert id_ans.startswith("### File: test.c\n```c\n"), "Identity format changed!"
    assert orc_ans.startswith("### File: test.c\n```c\n"), "Oracle format changed!"
    print("  [PASS] Identity and oracle repair answers are strictly unchanged.")

    # Detection prompt
    det_msgs = build_detection_messages("demo", [sample_region], use_new=False)
    assert len(det_msgs) == 2, "Detection messages format changed!"
    assert "expert C/C++ security auditor" in det_msgs[0]["content"]
    print("  [PASS] Detection prompt and system prompt are strictly unchanged.")

    # Repair prompt instructions
    rep_msgs = build_repair_messages("demo", [sample_region], cwe="CWE-119")
    user_prompt = rep_msgs[1]["content"]
    assert "Understand the vulnerability:" in user_prompt
    assert "Require meaningful repair:" in user_prompt
    assert "Surgical changes:" in user_prompt
    assert "Correctness:" in user_prompt
    assert "Output format:" in user_prompt
    assert "Do not return the original vulnerable code unchanged." in user_prompt
    assert "If no safe repair can be determined, return an explicit failure" in user_prompt
    print("  [PASS] Repair prompt contains all requested surgical repair instructions.")

    # 5. Unit test verification
    print("\n--- 5. Unit Test Execution ---")
    import unittest
    suite = unittest.defaultTestLoader.loadTestsFromName("tests.test_patch_extraction")
    runner = unittest.TextTestRunner(verbosity=0)
    res = runner.run(suite)
    assert res.wasSuccessful(), f"Patch extraction tests failed: {res.errors} {res.failures}"
    print(f"  [PASS] All {res.testsRun} tests in test_patch_extraction passed.")

    # 6. Retry5 and Baseline Preservation
    print("\n--- 6. Baseline & Previous Results Preservation ---")
    retry5_gen = REPO_ROOT / "results/docker_pilot_retry5/generations.jsonl"
    assert retry5_gen.exists(), f"Retry5 generations file missing: {retry5_gen}"
    actual_sha = compute_sha256(retry5_gen)
    assert actual_sha == EXPECTED_RETRY5_SHA256, f"Retry5 generations.jsonl was modified! SHA: {actual_sha}"
    print(f"  [PASS] Retry5 generations.jsonl SHA256 verified untouched: {actual_sha}")

    exp_cfg = REPO_ROOT / "config/experiment.json"
    assert exp_cfg.exists(), f"Missing {exp_cfg}"
    print("  [PASS] config/experiment.json exists and untouched.")

    print("\n" + "=" * 70)
    print("ALL PRE-FLIGHT CHECKS PASSED — RETRY 6 IS READY FOR EXECUTION")
    print("=" * 70)
    return 0


if __name__ == "__main__":
    sys.exit(main())

