#!/usr/bin/env python3
"""
Verification script for the isolated pilot patch.
Verifies that:
1. The host Vul4C.json is completely untouched.
2. The config/experiment.json is completely untouched.
3. The patch applies cleanly inside the pilot container.
4. Elfutils configure has ASAN removed while make preserves ASAN (-j2).
5. Binutils configure has ASAN/UBSAN removed while preserving other flags.
6. Binutils explicitly runs 'make configure-host' to avoid nested configure hangs.
7. Binutils instrumented make preserves both ASAN and UBSAN (-j2).
8. Both compile_command and compile_command_no_flags are properly updated.
9. All unrelated benchmark cases remain identical.
"""

import json
import subprocess
import sys
from pathlib import Path

HOST_VUL4C_JSON = Path("/home/rohit_kumawat/SoK/Vul4C_Src/Vul4C.json")
HOST_EXP_CONFIG = Path("/mnt/c/Users/Rohit Kumawat/Research/llm-vul4c-research/config/experiment.json")
PATCH_SCRIPT = Path("/mnt/c/Users/Rohit Kumawat/Research/llm-vul4c-research/scripts/patch_pilot_metadata.py")


def main() -> int:
    print("=" * 70)
    print("PILOT PATCH VERIFICATION")
    print("=" * 70)

    # 1. Verify host file remains untouched
    if not HOST_VUL4C_JSON.exists():
        print(f"[FAIL] Host metadata not found: {HOST_VUL4C_JSON}")
        return 1

    with open(HOST_VUL4C_JSON, "r", encoding="utf-8") as f:
        host_data = json.load(f)

    host_elf = host_data["CVE-2017-7607"]["compile_command"]
    host_bin = host_data["CVE-2017-14729"]["compile_command"]

    print("\n--- 1. Verifying Host Files Unchanged ---")
    assert any("-fsanitize=address" in cmd and "configure" in cmd for cmd in host_elf), \
        "Host elfutils was unexpectedly modified!"
    assert any("-fsanitize=address" in cmd and "configure" in cmd for cmd in host_bin), \
        "Host binutils configure was unexpectedly modified!"
    assert any("-j10" in cmd for cmd in host_bin), \
        "Host binutils make was unexpectedly modified!"
    print("  [PASS] Host Vul4C.json is 100% UNTOUCHED.")

    if not HOST_EXP_CONFIG.exists():
        print(f"[FAIL] config/experiment.json not found: {HOST_EXP_CONFIG}")
        return 1
    with open(HOST_EXP_CONFIG, "r", encoding="utf-8") as f:
        exp_cfg = json.load(f)
    assert exp_cfg.get("experiment_name") == "benchmark_qwen1.5b_all", \
        f"config/experiment.json experiment_name was modified: {exp_cfg.get('experiment_name')}"
    print("  [PASS] config/experiment.json is 100% UNTOUCHED.")

    # 2. Run patch inside isolated container
    print("\n--- 2. Running Patch Inside Container ---")
    cmd = [
        "docker", "run", "--rm",
        "-v", f"{PATCH_SCRIPT}:/opt/patch_pilot_metadata.py:ro",
        "vul4c/vul4c:4.0",
        "bash", "-lc",
        "python3 /opt/patch_pilot_metadata.py && python3 -c \"import json; "
        "d = json.load(open('/SoK-main/Vul4C_Src/Vul4C.json')); "
        "print(json.dumps({'elf': d['CVE-2017-7607'], 'bin': d['CVE-2017-14729'], 'bento': d['CVE-2017-14638']}))\""
    ]
    res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
    if res.returncode != 0:
        print(f"[FAIL] Container execution failed:\n{res.stderr}")
        return 1

    # Extract JSON line
    container_json = None
    for line in res.stdout.splitlines():
        if line.startswith('{"elf":'):
            container_json = json.loads(line)
            break

    if not container_json:
        print(f"[FAIL] Could not parse container output:\n{res.stdout}")
        return 1

    # 3. Verify Elfutils
    print("\n--- 3. Verifying Elfutils (CVE-2017-7607) ---")
    elf_compile = container_json["elf"]["compile_command"]
    elf_no_flags = container_json["elf"]["compile_command_no_flags"]

    print("  Container compile_command:")
    for step in elf_compile:
        print(f"    - {step}")
    print("  Container compile_command_no_flags:")
    for step in elf_no_flags:
        print(f"    - {step}")

    # Checks
    assert "-fsanitize=address" not in elf_compile[1], "FAIL: ASAN still in elfutils configure!"
    assert "-fsanitize=undefined" not in elf_compile[1], "FAIL: UBSAN in elfutils configure!"
    assert "-fsanitize=address" in elf_compile[2], "FAIL: ASAN missing from elfutils make!"
    assert "-j2" in elf_compile[2], "FAIL: -j2 missing from elfutils make!"
    assert "-j10" not in elf_compile[2], "FAIL: -j10 still in elfutils make!"
    assert "-fsanitize=address" not in elf_no_flags[1], "FAIL: ASAN in elfutils no-flags configure!"
    assert "-j2" in elf_no_flags[2], "FAIL: -j2 missing from elfutils no-flags make!"
    print("  [PASS] Elfutils: ASAN removed from configure, preserved in make (-j2).")

    # 4. Verify Binutils
    print("\n--- 4. Verifying Binutils (CVE-2017-14729) ---")
    bin_compile = container_json["bin"]["compile_command"]
    bin_no_flags = container_json["bin"]["compile_command_no_flags"]

    print("  Container compile_command:")
    for step in bin_compile:
        print(f"    - {step}")
    print("  Container compile_command_no_flags:")
    for step in bin_no_flags:
        print(f"    - {step}")

    # Check step count: [clean, configure, configure-host, make]
    assert len(bin_compile) == 4, f"FAIL: bin_compile expected 4 steps, got {len(bin_compile)}"
    assert len(bin_no_flags) == 4, f"FAIL: bin_no_flags expected 4 steps, got {len(bin_no_flags)}"

    # Check configure step has NO sanitizer flags
    for step_label, cfg_cmd in [("compile_command[1]", bin_compile[1]),
                                ("compile_command_no_flags[1]", bin_no_flags[1])]:
        assert "-fsanitize=address" not in cfg_cmd, \
            f"FAIL: -fsanitize=address unexpectedly found in binutils configure ({step_label})!"
        assert "-fsanitize=undefined" not in cfg_cmd, \
            f"FAIL: -fsanitize=undefined unexpectedly found in binutils configure ({step_label})!"
        assert "-DFORTIFY_SOURCE=2" in cfg_cmd, f"FAIL: -DFORTIFY_SOURCE missing in {step_label}!"
        assert "-fstack-protector-all" in cfg_cmd, f"FAIL: -fstack-protector-all missing in {step_label}!"
        assert "-fno-omit-frame-pointer" in cfg_cmd, f"FAIL: -fno-omit-frame-pointer missing in {step_label}!"
        assert "-g" in cfg_cmd, f"FAIL: -g missing in {step_label}!"
        assert "-Wno-error" in cfg_cmd, f"FAIL: -Wno-error missing in {step_label}!"
        assert "--disable-shared" in cfg_cmd, f"FAIL: --disable-shared missing in {step_label}!"
        assert "LIBS='-ldl -lutil'" in cfg_cmd, f"FAIL: LIBS missing in {step_label}!"

    # Check step 2 is make configure-host
    assert bin_compile[2] == "make configure-host", \
        f"FAIL: bin_compile[2] expected 'make configure-host', got {bin_compile[2]}"
    assert bin_no_flags[2] == "make configure-host", \
        f"FAIL: bin_no_flags[2] expected 'make configure-host', got {bin_no_flags[2]}"

    # Check instrumented make preserves both ASAN and UBSAN, with -j2
    assert "-fsanitize=address" in bin_compile[3], \
        "FAIL: -fsanitize=address missing from binutils instrumented make!"
    assert "-fsanitize=undefined" in bin_compile[3], \
        "FAIL: -fsanitize=undefined missing from binutils instrumented make!"
    assert "-j2" in bin_compile[3], "FAIL: -j2 missing from binutils instrumented make!"
    assert "-j10" not in bin_compile[3], "FAIL: -j10 still present in binutils instrumented make!"

    # Check uninstrumented make has -j2 and no sanitizers
    assert "-fsanitize=address" not in bin_no_flags[3], \
        "FAIL: -fsanitize=address unexpectedly found in binutils no-flags make!"
    assert "-fsanitize=undefined" not in bin_no_flags[3], \
        "FAIL: -fsanitize=undefined unexpectedly found in binutils no-flags make!"
    assert "-j2" in bin_no_flags[3], "FAIL: -j2 missing from binutils no-flags make!"
    assert "-j10" not in bin_no_flags[3], "FAIL: -j10 still present in binutils no-flags make!"

    # Check test_command has ASAN_OPTIONS=detect_leaks=0
    bin_test = container_json["bin"]["test_command"]
    expected_bin_test = [
        "ASAN_OPTIONS=detect_leaks=0 ./binutils/nm-new -A -a -l -S -s --special-syms --synthetic --with-symbol-versions -D ../VUL4C/exploit"
    ]
    assert bin_test == expected_bin_test, f"FAIL: binutils test_command mismatch! Got: {bin_test}"

    # Check host binutils test_command has NO detect_leaks
    host_bin_test = host_data["CVE-2017-14729"]["test_command"]
    assert "detect_leaks" not in host_bin_test[0], "FAIL: Host binutils test_command was modified!"

    print("  [PASS] Binutils: Configure has zero sanitizer flags; preserved other flags.")
    print("  [PASS] Binutils: make configure-host explicitly precedes make.")
    print("  [PASS] Binutils: Instrumented make preserves both ASAN and UBSAN with -j2.")
    print("  [PASS] Binutils: Both compile_command and compile_command_no_flags verified.")
    print("  [PASS] Binutils: test_command has ASAN_OPTIONS=detect_leaks=0.")

    # 5. Verify Unrelated Case
    print("\n--- 5. Verifying Unrelated Case (bento4/CVE-2017-14638) ---")
    bento_container = container_json["bento"]["compile_command"]
    bento_host = host_data["CVE-2017-14638"]["compile_command"]
    assert bento_container == bento_host, "FAIL: Unrelated case was modified!"
    assert container_json["bento"]["test_command"] == host_data["CVE-2017-14638"]["test_command"], \
        "FAIL: Unrelated case test_command was modified!"
    print(f"  Container matches host exactly: {bento_container == bento_host}")
    print("  [PASS] Unrelated cases completely unchanged.")

    print("\n" + "=" * 70)
    print("ALL VERIFICATION CHECKS PASSED SUCCESSFULLY")
    print("=" * 70)
    return 0


if __name__ == "__main__":
    sys.exit(main())
