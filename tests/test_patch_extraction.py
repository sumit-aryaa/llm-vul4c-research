"""Regression and reliability tests for patch extraction and answer parsing.

Covers:
1. Normal single fenced C/C++ code block.
2. Multiple legitimate code blocks (with REGION headings and order-matched).
3. Echoed prompt header followed by a substantive source-code block (Retry 5 Binutils and Elfutils).
4. Nested or repeated opening fences.
5. Output containing only prompt scaffolding.
6. Empty or malformed model output.
7. Existing valid repair formats (oracle/identity, bare code, whitespace normalization).
"""

import json
from pathlib import Path
import unittest

from pipeline.patch_manager import (
    extract_code_blocks,
    is_substantive_code,
    parse_region_answers,
    strip_scaffolding,
)
from pipeline.task_prompts import identity_repair_answer, oracle_repair_answer
from pipeline.patch_manager import extract_regions


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


if __name__ == "__main__":
    unittest.main()

