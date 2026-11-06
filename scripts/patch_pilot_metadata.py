#!/usr/bin/env python3
"""
Patch Vul4C benchmark metadata inside the isolated Docker evaluation container.
This modifies only the in-container /SoK-main/Vul4C_Src/Vul4C.json before checkout.
The host repository and host benchmark files remain completely untouched.
"""

import json
import os
import sys

DEFAULT_TARGET = "/SoK-main/Vul4C_Src/Vul4C.json"


def patch_metadata(target_path: str = DEFAULT_TARGET) -> None:
    if not os.path.exists(target_path):
        raise FileNotFoundError(f"Target metadata file not found: {target_path}")

    with open(target_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    # 1. elfutils/CVE-2017-7607
    # Remove ASAN from ./configure (avoids conftest hang in WSL Docker).
    # Keep ASAN in make build (preserves vulnerability reproduction).
    if "CVE-2017-7607" in data:
        data["CVE-2017-7607"]["compile_command"] = [
            "make clean",
            './configure --enable-shared=no CFLAGS="-Wno-error -g" CXXFLAGS="-Wno-error -g"',
            'make CFLAGS="-Wno-error -fsanitize=address -fno-omit-frame-pointer -g" '
            'CXXFLAGS="-Wno-error -fsanitize=address -fno-omit-frame-pointer -g" '
            'LDFLAGS="-fsanitize=address -fno-omit-frame-pointer" -j2',
        ]
        data["CVE-2017-7607"]["compile_command_no_flags"] = [
            "make clean",
            './configure --enable-shared=no CFLAGS="-Wno-error -g" CXXFLAGS="-Wno-error -g"',
            "make -j2",
        ]

    # 2. binutils/CVE-2017-14729
    # - Top-level ./configure with clean CFLAGS/CXXFLAGS (no ASAN/UBSAN).
    # - Run 'make configure-host' before make to configure all subdirectories
    #   (libiberty, intl, bfd, opcodes, binutils, etc.) cleanly upfront.
    #   This prevents nested sub-configure scripts from inheriting ASAN/UBSAN
    #   from the parent make and hanging on conftest checks.
    # - Instrumented make passes ASAN and UBSAN to build objects/executables with -j2.
    # - compile_command_no_flags builds without sanitizers with -j2.
    if "CVE-2017-14729" in data:
        bin_cflags = "-DFORTIFY_SOURCE=2 -fstack-protector-all -fno-omit-frame-pointer -g -Wno-error"
        bin_configure_clean = (
            f"ASAN_OPTIONS=detect_leaks=0 CC=gcc CXX=g++ "
            f'CFLAGS="{bin_cflags}" '
            f'CXXFLAGS="{bin_cflags}" '
            f"./configure --disable-shared --disable-gdb --disable-libdecnumber --disable-readline --disable-sim "
            f"LIBS='-ldl -lutil'"
        )
        bin_make_instrumented = (
            'make CFLAGS="-ldl -lutil -fsanitize=address -fsanitize=undefined -g" '
            'CXXFLAGS="-fsanitize=address -fsanitize=undefined -ldl -lutil -g" '
            'LDFLAGS=" -ldl -lutil -fsanitize=address -fsanitize=undefined" -j2'
        )
        data["CVE-2017-14729"]["compile_command"] = [
            "make clean",
            bin_configure_clean,
            "make configure-host",
            bin_make_instrumented,
        ]
        data["CVE-2017-14729"]["compile_command_no_flags"] = [
            "make clean",
            bin_configure_clean,
            "make configure-host",
            "make -j2",
        ]
        # Exploit reproduction: disable LeakSanitizer for nm-new execution to avoid false-negative crash detection.
        # Genuine memory errors (heap-buffer-overflow) still trigger AddressSanitizer aborts.
        data["CVE-2017-14729"]["test_command"] = [
            "ASAN_OPTIONS=detect_leaks=0 ./binutils/nm-new -A -a -l -S -s --special-syms --synthetic --with-symbol-versions -D ../VUL4C/exploit"
        ]

    with open(target_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4)

    print(f"[OK] Patched {target_path} successfully for pilot.")


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_TARGET
    patch_metadata(target)
