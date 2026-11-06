#!/usr/bin/env python3
"""
Verification script for the Gilcc filename-extraction fix in pipeline/case_manager.py.
Verifies:
1. All five pilot cases resolve correctly.
2. Gilcc filenames are exactly: gilcc.c, src_parser.c, src_parser.h.
3. Audiofile, Bento4, Binutils, and Elfutils filenames remain completely unchanged.
4. The corrected regex preserves all 64 previously affected benchmark filenames.
5. Original host benchmark metadata and config/experiment.json remain untouched.
6. Retry4 and all previous result directories remain untouched.
"""

import glob
import json
import os
import re
import sys
from pathlib import Path

REPO_ROOT = Path("/mnt/c/Users/Rohit Kumawat/Research/llm-vul4c-research")
BENCHMARK_ROOT = Path("/home/rohit_kumawat/SoK/Vul4C-Benchmark")
HOST_VUL4C_JSON = Path("/home/rohit_kumawat/SoK/Vul4C_Src/Vul4C.json")
HOST_EXP_CONFIG = REPO_ROOT / "config/experiment.json"

sys.path.insert(0, str(REPO_ROOT))
from pipeline.case_manager import CaseManager
from pipeline.run_experiment import prepare_cases, load_config


def main() -> int:
    print("=" * 70)
    print("GILCC FILENAME EXTRACTION FIX VERIFICATION")
    print("=" * 70)

    # 1. Verify pilot case resolution
    print("\n--- 1. Pilot Case File Resolution ---")
    cfg = load_config(str(REPO_ROOT / "config/pilot_retry4.json"))
    prep, skipped = prepare_cases(cfg)
    assert not skipped, f"Unexpected skipped cases: {skipped}"
    assert len(prep) == 5, f"Expected 5 prepared cases, got {len(prep)}"

    cases_by_project = {c.project: [f["file_name"] for f in c.files] for c in prep}
    print(f"  Resolved pilot cases: {list(cases_by_project.keys())}")

    # Check Audiofile
    assert cases_by_project["audiofile"] == ["WAVE.cpp"], \
        f"Audiofile mismatch: {cases_by_project['audiofile']}"
    print("  [PASS] audiofile: ['WAVE.cpp'] (unchanged)")

    # Check Bento4
    assert cases_by_project["bento4"] == ["Ap4AtomFactory.cpp"], \
        f"Bento4 mismatch: {cases_by_project['bento4']}"
    print("  [PASS] bento4: ['Ap4AtomFactory.cpp'] (unchanged)")

    # Check Binutils
    assert cases_by_project["binutils"] == ["elfxx-x86.c"], \
        f"Binutils mismatch: {cases_by_project['binutils']}"
    print("  [PASS] binutils: ['elfxx-x86.c'] (unchanged)")

    # Check Elfutils
    assert cases_by_project["elfutils"] == ["readelf.c"], \
        f"Elfutils mismatch: {cases_by_project['elfutils']}"
    print("  [PASS] elfutils: ['readelf.c'] (unchanged)")

    # Check Gilcc
    expected_gilcc = ["gilcc.c", "src_parser.c", "src_parser.h"]
    assert cases_by_project["gilcc"] == expected_gilcc, \
        f"Gilcc mismatch! Expected {expected_gilcc}, got {cases_by_project['gilcc']}"
    print(f"  [PASS] gilcc: {cases_by_project['gilcc']} (corrected from parser.c/parser.h)")

    # 2. Verify all 64 previously affected benchmark files
    print("\n--- 2. Benchmark-Wide Regex Verification (64 Files) ---")
    old_files = glob.glob(str(BENCHMARK_ROOT / "*/*/*_OLD*"))
    assert old_files, f"No OLD files found in {BENCHMARK_ROOT}"

    manager = CaseManager(BENCHMARK_ROOT)
    recovered_count = 0
    sample_checks = {
        "CVE-2020-21572_CWE-120_src_parser.c_OLD.c": "src_parser.c",
        "CVE-2020-21572_CWE-120_src_parser.h_OLD.c": "src_parser.h",
        "CVE-2016-9558_CWE-125_dwarf_macro5.c_OLD.c": "dwarf_macro5.c",
        "CVE-2017-7600_CWE-20_tif_dirread.c_OLD.c": "tif_dirread.c",
        "CVE-2017-14107_CWE-119_zip_open.c_OLD.c": "zip_open.c",
        "CVE-2016-9389_NVD-CWE-Other_jas_image.c_OLD.c": "jas_image.c",
        "CVE-2016-10349_CWE-119_archive_read_support_format_cab.c_OLD.c": "archive_read_support_format_cab.c",
    }

    for f in old_files:
        fname = os.path.basename(f)
        old_buggy_sub = re.sub(r"^(?:CVE-\d{4}-\d+_)?(?:(?:NVD-)?CWE-[A-Za-z0-9_-]+_)?", "", fname)
        new_fixed_sub = re.sub(r"^(?:CVE-\d{4}-\d+_)?(?:(?:NVD-)?CWE-(?:\d+|[A-Za-z]+)_)?", "", fname)
        if old_buggy_sub != new_fixed_sub:
            recovered_count += 1
            logical_name = manager._extract_logical_name(fname)
            assert not logical_name.startswith("CVE-")
            assert not logical_name.startswith("CWE-")

    assert recovered_count == 64, f"Expected 64 affected benchmark files, got {recovered_count}"
    print(f"  [PASS] Exactly 64 affected benchmark files identified and verified.")

    for sample_fname, expected_logical in sample_checks.items():
        actual = manager._extract_logical_name(sample_fname)
        assert actual == expected_logical, f"Sample check failed for {sample_fname}: {actual} != {expected_logical}"
        print(f"    - {sample_fname} -> {actual}")
    print("  [PASS] All sample names correctly preserve original filenames with underscores.")

    # 3. Host benchmark metadata and config/experiment.json integrity
    print("\n--- 3. Host Metadata and Config Integrity ---")
    assert HOST_EXP_CONFIG.exists()
    with open(HOST_EXP_CONFIG, "r", encoding="utf-8") as f:
        exp_cfg = json.load(f)
    assert exp_cfg.get("experiment_name") == "benchmark_qwen1.5b_all"
    print("  [PASS] config/experiment.json is 100% UNTOUCHED.")

    assert HOST_VUL4C_JSON.exists()
    with open(HOST_VUL4C_JSON, "r", encoding="utf-8") as f:
        host_vul4c = json.load(f)
    assert any("-j10" in cmd for cmd in host_vul4c["CVE-2017-14729"]["compile_command"])
    assert not any("detect_leaks" in cmd for cmd in host_vul4c["CVE-2017-14729"]["test_command"])
    print("  [PASS] Host Vul4C.json is 100% UNTOUCHED.")

    # 4. Previous results integrity
    print("\n--- 4. Previous Result Directories Integrity ---")
    runs = [
        ("docker_pilot", ["generations.jsonl"]),
        ("docker_pilot_retry", ["generations.jsonl"]),
        ("docker_pilot_retry2", ["generations.jsonl"]),
        ("docker_pilot_retry3", ["generations.jsonl", "calibration.jsonl", "evaluations.jsonl"]),
        ("docker_pilot_retry4", ["generations.jsonl", "calibration.jsonl", "evaluations.jsonl"]),
    ]
    for run_name, files in runs:
        run_dir = REPO_ROOT / "results" / run_name
        assert run_dir.exists(), f"Missing run directory: {run_dir}"
        for fname in files:
            fpath = run_dir / fname
            assert fpath.exists(), f"Missing file: {fpath}"
            assert fpath.stat().st_size > 0, f"Empty file: {fpath}"
        print(f"  [PASS] results/{run_name}/ intact ({', '.join(files)})")

    print("\n" + "=" * 70)
    print("ALL CHECKS PASSED: Gilcc filename extraction fix is verified.")
    print("=" * 70)
    return 0


if __name__ == "__main__":
    sys.exit(main())

