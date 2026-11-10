"""Regression and reliability tests for patch extraction and answer parsing.

Covers:
1. Normal single fenced C/C++ code block.
2. Multiple legitimate code blocks (with REGION headings and order-matched).
3. Echoed prompt header followed by a substantive source-code block (Retry 5 Binutils and Elfutils).
4. Nested or repeated opening fences.
5. Output containing only prompt scaffolding.
6. Empty or malformed model output.
7. Existing valid repair formats (oracle/identity, bare code, whitespace normalization).
8. Byte-exact round trip of unchanged answers (blank lines at region edges), incl. the full benchmark.
9. Frozen repair prompt versions.
"""

import hashlib
import json
import logging
import os
from pathlib import Path
import unittest

from pipeline.patch_manager import (
    extract_code_blocks,
    is_substantive_code,
    parse_region_answers,
    strip_scaffolding,
)
from pipeline.task_prompts import build_repair_messages, identity_repair_answer, oracle_repair_answer
from pipeline.patch_manager import CodeRegion, extract_regions

# sha256 of the repair user prompt for the fixed sample in TestRepairPromptVersions.
# A change here means the prompt text changed: add a new version instead of editing v1/v2.
V1_PROMPT_SHA256 = "82b6c9397391a0c6dc8200e4014db107ee623da1e8eb36ff7198ee07e54735cf"
V2_PROMPT_SHA256 = "73b3aa2ca29017f2d0119ee5c2265fbd36722d03d7a01c1a4b39b8678f6fa80d"


class TestPatchExtraction(unittest.TestCase):

    # ------------------------------------------------------------------ #
    # 1. Normal single fenced C/C++ code block
    # ------------------------------------------------------------------ #

    def test_normal_single_fenced_c_code(self):
        text = "```c\nint add(int a, int b) {\n    return a + b;\n}\n```"
        blocks = extract_code_blocks(text)
        self.assertEqual(len(blocks), 1)
        self.assertEqual(blocks[0], "int add(int a, int b) {\n    return a + b;\n}\n")

        answers, warnings = parse_region_answers(text, 1)
        self.assertEqual(warnings, [])
        self.assertEqual(answers, {0: "int add(int a, int b) {\n    return a + b;\n}\n"})

    def test_normal_single_fenced_cpp_code_with_surrounding_prose(self):
        text = (
            "Here is the fixed C++ function:\n\n"
            "```cpp\n"
            "class SafeBuffer {\n"
            "public:\n"
            "    explicit SafeBuffer(size_t sz) : size_(sz) {}\n"
            "private:\n"
            "    size_t size_;\n"
            "};\n"
            "```\n\n"
            "This fixes the buffer issue."
        )
        answers, warnings = parse_region_answers(text, 1)
        self.assertEqual(warnings, [])
        self.assertIn("class SafeBuffer", answers[0])
        self.assertNotIn("Here is the fixed", answers[0])
        self.assertNotIn("This fixes the buffer", answers[0])

    # ------------------------------------------------------------------ #
    # 2. Multiple legitimate code blocks
    # ------------------------------------------------------------------ #

    def test_multiple_blocks_with_region_headings(self):
        text = (
            "### REGION 1: file1.c\n"
            "```c\n"
            "int func1(void) {\n"
            "    return 1;\n"
            "}\n"
            "```\n\n"
            "### REGION 2: file2.c\n"
            "```c\n"
            "int func2(void) {\n"
            "    return 2;\n"
            "}\n"
            "```\n"
        )
        answers, warnings = parse_region_answers(text, 2)
        self.assertEqual(warnings, [])
        self.assertEqual(len(answers), 2)
        self.assertEqual(answers[0], "int func1(void) {\n    return 1;\n}\n")
        self.assertEqual(answers[1], "int func2(void) {\n    return 2;\n}\n")

    def test_multiple_blocks_ordered_without_headings(self):
        text = (
            "```c\n"
            "int func1(void) { return 1; }\n"
            "```\n\n"
            "```c\n"
            "int func2(void) { return 2; }\n"
            "```\n"
        )
        answers, warnings = parse_region_answers(text, 2)
        self.assertEqual(warnings, ["regions_matched_by_order"])
        self.assertEqual(answers[0], "int func1(void) { return 1; }\n")
        self.assertEqual(answers[1], "int func2(void) { return 2; }\n")

    # ------------------------------------------------------------------ #
    # 3. Echoed prompt header followed by substantive code (Retry5)
    # ------------------------------------------------------------------ #

    def test_echoed_header_followed_by_code_synthetic(self):
        text = (
            "```c\n"
            "[BEGIN UNTRUSTED SOURCE CODE]\n"
            "### File: buffer.c\n"
            "```c\n"
            "void secure_copy(char *dst, const char *src, size_t n) {\n"
            "    if (n > 0) {\n"
            "        strncpy(dst, src, n - 1);\n"
            "        dst[n - 1] = '\\0';\n"
            "    }\n"
            "}\n"
            "```\n"
        )
        blocks = extract_code_blocks(text)
        self.assertEqual(len(blocks), 2)
        self.assertFalse(is_substantive_code(blocks[0]))
        self.assertTrue(is_substantive_code(blocks[1]))

        answers, warnings = parse_region_answers(text, 1)
        self.assertEqual(warnings, [])
        self.assertEqual(len(answers), 1)
        self.assertNotIn("[BEGIN UNTRUSTED SOURCE CODE]", answers[0])
        self.assertNotIn("### File:", answers[0])
        self.assertTrue(answers[0].startswith("void secure_copy"))

    def test_scaffolding_inside_same_block_without_inner_fence(self):
        text = (
            "```c\n"
            "[BEGIN UNTRUSTED SOURCE CODE]\n"
            "### File: buffer.c\n"
            "void secure_copy(char *dst, const char *src, size_t n) {\n"
            "    return;\n"
            "}\n"
            "[END UNTRUSTED SOURCE CODE]\n"
            "```\n"
        )
        answers, warnings = parse_region_answers(text, 1)
        self.assertEqual(warnings, [])
        self.assertEqual(len(answers), 1)
        self.assertNotIn("[BEGIN UNTRUSTED SOURCE CODE]", answers[0])
        self.assertNotIn("[END UNTRUSTED SOURCE CODE]", answers[0])
        self.assertNotIn("### File:", answers[0])
        self.assertEqual(answers[0].strip(), "void secure_copy(char *dst, const char *src, size_t n) {\n    return;\n}")

    def test_c_preprocessor_directives_not_discarded(self):
        text = (
            "```c\n"
            "#include <stdio.h>\n"
            "#define REGION_LIMIT 1024\n"
            "#ifdef REGION\n"
            "#pragma once\n"
            "int init(void) { return 0; }\n"
            "```\n"
        )
        self.assertTrue(is_substantive_code(text))
        answers, warnings = parse_region_answers(text, 1)
        self.assertEqual(warnings, [])
        self.assertIn("#include <stdio.h>", answers[0])
        self.assertIn("#define REGION_LIMIT 1024", answers[0])
        self.assertIn("#ifdef REGION", answers[0])

    def test_multi_region_with_scaffolding_in_one_region(self):
        text = (
            "### REGION 1: file1.c\n"
            "```c\n"
            "[BEGIN UNTRUSTED SOURCE CODE]\n"
            "### File: file1.c\n"
            "```\n"
            "```c\n"
            "int part1(void) { return 1; }\n"
            "```\n\n"
            "### REGION 2: file2.c\n"
            "```c\n"
            "int part2(void) { return 2; }\n"
            "```\n"
        )
        answers, warnings = parse_region_answers(text, 2)
        self.assertEqual(warnings, [])
        self.assertEqual(len(answers), 2)
        self.assertEqual(answers[0].strip(), "int part1(void) { return 1; }")
        self.assertEqual(answers[1].strip(), "int part2(void) { return 2; }")

    def test_retry5_binutils_raw_output_regression(self):
        fixture_path = Path("results/docker_pilot_retry5/generations.jsonl")
        if not fixture_path.exists():
            self.skipTest("Retry5 generations file not found")

        raw_output = None
        with open(fixture_path, encoding="utf-8") as f:
            for line in f:
                rec = json.loads(line)
                if (
                    rec.get("task") == "repair"
                    and rec.get("model") == "ollama-qwen-1.5b"
                    and "binutils" in rec.get("case_key", "")
                ):
                    raw_output = rec.get("output")
                    break

        self.assertIsNotNone(raw_output, "Binutils raw output fixture found")
        answers, warnings = parse_region_answers(raw_output, 1)
        self.assertEqual(warnings, [])
        self.assertEqual(len(answers), 1)
        ans = answers[0]

        # Crucial assertions: Must not be the 2-line header, must be the 208-line C function
        self.assertNotIn("[BEGIN UNTRUSTED SOURCE CODE]", ans)
        self.assertNotIn("### File: elfxx-x86.c", ans)
        lines = ans.splitlines()
        self.assertEqual(len(lines), 208)
        self.assertEqual(lines[0].strip(), "long")
        self.assertIn("_bfd_x86_elf_get_synthetic_symtab", lines[1])
        self.assertEqual(lines[-1].strip(), "}")

    def test_retry5_elfutils_raw_output_regression(self):
        fixture_path = Path("results/docker_pilot_retry5/generations.jsonl")
        if not fixture_path.exists():
            self.skipTest("Retry5 generations file not found")

        raw_output = None
        with open(fixture_path, encoding="utf-8") as f:
            for line in f:
                rec = json.loads(line)
                if (
                    rec.get("task") == "repair"
                    and rec.get("model") == "ollama-qwen-1.5b"
                    and "elfutils" in rec.get("case_key", "")
                ):
                    raw_output = rec.get("output")
                    break

        self.assertIsNotNone(raw_output, "Elfutils raw output fixture found")
        answers, warnings = parse_region_answers(raw_output, 1)
        self.assertEqual(warnings, [])
        self.assertEqual(len(answers), 1)
        ans = answers[0]

        # Crucial assertions: Must not be markdown scaffolding, must be handle_gnu_hash
        self.assertNotIn("[BEGIN UNTRUSTED SOURCE CODE]", ans)
        self.assertNotIn("### File: readelf.c", ans)
        lines = ans.splitlines()
        self.assertEqual(len(lines), 100)
        self.assertEqual(lines[0].strip(), "static void")
        self.assertIn("handle_gnu_hash", lines[1])
        self.assertEqual(lines[-1].strip(), "}")

    # ------------------------------------------------------------------ #
    # 4. Nested or repeated opening fences
    # ------------------------------------------------------------------ #

    def test_repeated_opening_fences_immediately_adjacent(self):
        text = "```c\n```c\nint foo(void) {\n    return 42;\n}\n```"
        blocks = extract_code_blocks(text)
        self.assertEqual(len(blocks), 1)
        self.assertEqual(blocks[0], "int foo(void) {\n    return 42;\n}\n")

        answers, warnings = parse_region_answers(text, 1)
        self.assertEqual(warnings, [])
        self.assertEqual(answers[0], "int foo(void) {\n    return 42;\n}\n")

    def test_repeated_opening_fences_empty_block(self):
        text = "```\n```cpp\nint bar(void) { return 0; }\n```"
        blocks = extract_code_blocks(text)
        self.assertEqual(len(blocks), 1)
        self.assertEqual(blocks[0], "int bar(void) { return 0; }\n")

        answers, warnings = parse_region_answers(text, 1)
        self.assertEqual(warnings, [])
        self.assertEqual(answers[0], "int bar(void) { return 0; }\n")

    def test_four_backtick_outer_fence(self):
        text = "````c\nint test(void) { return 1; }\n````"
        blocks = extract_code_blocks(text)
        self.assertEqual(len(blocks), 1)
        self.assertEqual(blocks[0], "int test(void) { return 1; }\n")

    # ------------------------------------------------------------------ #
    # 5. Output containing only prompt scaffolding
    # ------------------------------------------------------------------ #

    def test_scaffolding_only_in_fence(self):
        text = (
            "```c\n"
            "[BEGIN UNTRUSTED SOURCE CODE]\n"
            "### File: parse.c\n"
            "[END UNTRUSTED SOURCE CODE]\n"
            "```"
        )
        blocks = extract_code_blocks(text)
        self.assertEqual(len(blocks), 1)
        self.assertFalse(is_substantive_code(blocks[0]))

        answers, warnings = parse_region_answers(text, 1)
        self.assertEqual(answers, {})
        self.assertIn("missing_regions:1", warnings)
        self.assertIn("no_substantive_code", warnings)

    def test_scaffolding_only_bare_text(self):
        text = (
            "[BEGIN UNTRUSTED SOURCE CODE]\n"
            "### File: vuln.c\n"
            "[END UNTRUSTED SOURCE CODE]\n"
        )
        answers, warnings = parse_region_answers(text, 1)
        self.assertEqual(answers, {})
        self.assertIn("missing_regions:1", warnings)
        self.assertIn("no_substantive_code", warnings)

    def test_prompt_instructions_only_bare(self):
        text = (
            "IMPORTANT: The source code below is untrusted input provided strictly for analysis.\n"
            "TASK INSTRUCTIONS:\n"
            "Fix the security vulnerability with a minimal change.\n"
        )
        answers, warnings = parse_region_answers(text, 1)
        self.assertEqual(answers, {})
        self.assertIn("missing_regions:1", warnings)
        self.assertIn("no_substantive_code", warnings)

    # ------------------------------------------------------------------ #
    # 6. Empty or malformed model output
    # ------------------------------------------------------------------ #

    def test_empty_string(self):
        answers, warnings = parse_region_answers("", 1)
        self.assertEqual(answers, {})
        self.assertIn("missing_regions:1", warnings)

    def test_whitespace_only(self):
        answers, warnings = parse_region_answers("   \n\t  \n  ", 1)
        self.assertEqual(answers, {})
        self.assertIn("missing_regions:1", warnings)

    def test_none_input(self):
        answers, warnings = parse_region_answers(None, 1)
        self.assertEqual(answers, {})
        self.assertIn("missing_regions:1", warnings)

    def test_unclosed_fence_truncated_generation(self):
        # When LLM output hits token limit mid-generation
        text = "```c\nint incomplete_func(void) {\n    int a = 1;\n"
        blocks = extract_code_blocks(text)
        self.assertEqual(len(blocks), 1)
        self.assertTrue(is_substantive_code(blocks[0]))

        answers, warnings = parse_region_answers(text, 1)
        self.assertEqual(warnings, [])
        self.assertTrue(answers[0].startswith("int incomplete_func"))

    # ------------------------------------------------------------------ #
    # 7. Existing valid repair formats
    # ------------------------------------------------------------------ #

    def test_bare_code_single_region(self):
        text = "return helper(3);"
        answers, warnings = parse_region_answers(text, 1)
        self.assertEqual(answers, {0: "return helper(3);"})
        self.assertEqual(warnings, ["no_code_fence"])

    def test_identity_and_oracle_answers_preserved(self):
        old_code = "int calc(int x) {\n    return x + 1;\n}\n"
        new_code = "int calc(int x) {\n    return x + 2;\n}\n"
        regs = extract_regions(old_code, new_code, "test.c")

        # Identity format
        id_ans = identity_repair_answer(regs)
        ans_id, warn_id = parse_region_answers(id_ans, len(regs))
        self.assertEqual(warn_id, [])
        self.assertEqual(ans_id[0].strip(), old_code.strip())

        # Oracle format
        orc_ans = oracle_repair_answer(regs)
        ans_orc, warn_orc = parse_region_answers(orc_ans, len(regs))
        self.assertEqual(warn_orc, [])
        self.assertEqual(ans_orc[0].strip(), new_code.strip())


    # ------------------------------------------------------------------ #
    # 8. Byte-exact round trip (blank lines at region edges are code)
    # ------------------------------------------------------------------ #

    def _roundtrip(self, codes):
        regs = [CodeRegion(f"f{i}.c", i * 10, i * 10 + 3, i * 10, i * 10 + 3, c, c, "window")
                for i, c in enumerate(codes)]
        answers, warnings = parse_region_answers(identity_repair_answer(regs), len(regs))
        self.assertEqual(warnings, [])
        self.assertEqual([answers[i] for i in range(len(regs))], list(codes))

    def test_roundtrip_keeps_trailing_blank_lines(self):
        self._roundtrip(["int f(void) {\n    return 1;\n}\n\n"])
        self._roundtrip(["int f(void) {\n    return 1;\n}\n\n\n"])

    def test_roundtrip_keeps_leading_blank_lines(self):
        self._roundtrip(["\nint f(void) {\n    return 1;\n}\n"])
        self._roundtrip(["\n\n  \nint f(void) {\n    return 1;\n}\n"])

    def test_roundtrip_keeps_crlf_and_blank_edges(self):
        self._roundtrip(["\r\nint f(void) {\r\n    return 1;\r\n}\r\n\r\n"])

    def test_roundtrip_multi_region_blank_edges(self):
        self._roundtrip(["int a;\n\n", "\nint b;\n", "int c;\n"])

    def test_strip_scaffolding_leaves_plain_code_unchanged(self):
        for code in ("\nint a;\n\n", "int a;\n", "\n\n", "#include <x.h>\n\nint a;\n\n"):
            self.assertEqual(strip_scaffolding(code), code)

    def test_strip_scaffolding_removes_scaffolding_and_adjacent_blanks(self):
        text = "\n[BEGIN UNTRUSTED SOURCE CODE]\n### File: a.c\n\nint a;\n\n[END UNTRUSTED SOURCE CODE]\n\n"
        self.assertEqual(strip_scaffolding(text), "int a;\n")

    def test_identity_and_oracle_roundtrip_on_full_benchmark(self):
        """Set VUL4C_BENCHMARK_ROOT=/path/to/Vul4C-Benchmark to run on all cases."""
        root = os.environ.get("VUL4C_BENCHMARK_ROOT")
        if not root or not Path(root).is_dir():
            self.skipTest("VUL4C_BENCHMARK_ROOT not set")
        from pipeline.run_experiment import DEFAULTS, _merge, build_candidate, prepare_cases
        logging.disable(logging.WARNING)
        try:
            cases, _ = prepare_cases(_merge(DEFAULTS, {"benchmark_root": root}))
        finally:
            logging.disable(logging.NOTSET)
        self.assertGreater(len(cases), 0)
        broken = []
        for case in cases:
            n = len(case.regions)
            ident, _ = parse_region_answers(identity_repair_answer(case.regions), n)
            orac, _ = parse_region_answers(oracle_repair_answer(case.regions), n)
            ok = (all(ident.get(i) == r.old_code for i, r in enumerate(case.regions))
                  and all(orac.get(i) == r.new_code for i, r in enumerate(case.regions))
                  and not build_candidate(case, ident)["changed"]
                  and build_candidate(case, orac)["identical_to_reference"])
            if not ok:
                broken.append(case.case_key)
        self.assertEqual(broken, [], f"{len(broken)} of {len(cases)} cases do not round-trip")


class TestRepairPromptVersions(unittest.TestCase):
    """The repair prompt is frozen per version so model comparisons stay fair."""

    def setUp(self):
        self.regs = extract_regions("int f(int x) {\n    return x + 1;\n}\n",
                                    "int f(int x) {\n    return x + 2;\n}\n", "t.c")

    def _user(self, **kw):
        return build_repair_messages("demo", self.regs, cwe="CWE-119", **kw)[1]["content"]

    def test_default_is_v1_baseline_prompt(self):
        self.assertEqual(self._user(), self._user(prompt_version="v1"))
        self.assertEqual(hashlib.sha256(self._user().encode()).hexdigest(), V1_PROMPT_SHA256)

    def test_v2_is_pilot_prompt(self):
        self.assertIn("minimal, surgical repair", self._user(prompt_version="v2"))
        self.assertEqual(hashlib.sha256(self._user(prompt_version="v2").encode()).hexdigest(), V2_PROMPT_SHA256)

    def test_unknown_version_rejected(self):
        with self.assertRaises(ValueError):
            self._user(prompt_version="v3")


if __name__ == "__main__":
    unittest.main()

