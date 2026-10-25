"""Tests for the fine-tuning dataset builder and the LoRA training helpers (no GPU/network)."""

import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from tests.test_experiment_pipeline import OLD, write_fake_benchmark  # noqa: E402
from training import build_finetune_dataset as bfd  # noqa: E402
from training.train_lora import IGNORE_INDEX, encode_example  # noqa: E402

VULN = "int foo(char *b, int n)\n{\n    char t[8];\n    memcpy(t, b, n);\n    return t[0];\n}\n"
FIXED = VULN.replace("    memcpy", "    if (n > 8) return -1;\n    memcpy")


def rec(i, target, code, **kw):
    base = dict(idx=i, project="openssl", commit_id=f"{i:040x}", target=target, func=code,
                cwe=["CWE-787"], cve=f"CVE-2020-{1000 + i}", cve_desc="Heap overflow.", file_name="crypto/foo.c")
    base.update(kw)
    return base


class TestDatasetBuilder(unittest.TestCase):

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        write_fake_benchmark(self.tmp / "SoK" / "Vul4C-Benchmark")
        (self.tmp / "SoK" / "Vul4C_Src").mkdir()
        self.test_commit = "ab" * 20
        (self.tmp / "SoK" / "Vul4C_Src" / "Vul4C.json").write_text(json.dumps({
            "CVE-2099-0001": {"project": "demo", "hash": self.test_commit,
                              "get_command": ["git clone https://github.com/someone/demo-lib.git source"]}}))
        rows = []
        for i in range(30):
            rows += [rec(i, 1, VULN.replace("foo", f"f{i}")), rec(i, 0, FIXED.replace("foo", f"f{i}"))]
        rows += [rec(90, 1, VULN.replace("foo", "a"), cve="CVE-2099-0001"),
                 rec(90, 0, FIXED.replace("foo", "a"), cve="CVE-2099-0001")]
        rows += [rec(91, 1, VULN.replace("foo", "b"), commit_id=self.test_commit),
                 rec(91, 0, FIXED.replace("foo", "b"), commit_id=self.test_commit)]
        rows += [rec(92, 1, VULN.replace("foo", "c"), project="demo-lib"),
                 rec(92, 0, FIXED.replace("foo", "c"), project="demo-lib")]
        region = OLD.splitlines(True)[7:13]  # parse_header in the fake Vul4C case
        rows += [rec(93, 1, "".join(region)), rec(93, 0, "".join(region).replace("memcpy", "memmove"))]
        rows += [rec(94, 1, VULN.replace("foo", "d"))]  # unpaired
        rows += [{"func_before": VULN.replace("foo", "mv"), "func_after": FIXED.replace("foo", "mv"),
                  "commit_hash": "c" * 40, "repo_name": "zlib", "cve_id": "CVE-2021-1", "cwe_ids": ["CWE-120"]}]
        self.input = self.tmp / "pairs.jsonl"
        self.input.write_text("".join(json.dumps(r) + "\n" for r in rows))

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_leakage_removed_and_format_matches_pipeline(self):
        fp = bfd.vul4c_fingerprint(self.tmp / "SoK" / "Vul4C-Benchmark")
        self.assertIn("CVE-2099-0001", fp.cves)
        self.assertIn(self.test_commit, fp.commits)
        self.assertIn("demolib", fp.projects)
        out = self.tmp / "ft"
        m = bfd.build([self.input], fp, out, ["detection", "repair"], valid_fraction=0.3)
        f = m["filtering"]
        self.assertEqual(f["removed_leak_cve"], 1)
        self.assertEqual(f["removed_leak_commit"], 1)
        self.assertEqual(f["removed_leak_project"], 1)
        self.assertEqual(f["removed_leak_identical_code"], 1)
        self.assertEqual(f["skipped_unpaired_function"], 1)
        self.assertEqual(m["output"]["train_pairs"] + m["output"]["valid_pairs"], 31)  # 30 + MegaVul-style

        examples = [json.loads(line) for line in open(out / "train.jsonl")] + \
                   [json.loads(line) for line in open(out / "valid.jsonl")]
        text = json.dumps(examples)
        # (the detection instructions mention "parse_header()" as an example, so look for the code itself)
        for leaked in ("CVE-2099-0001", self.test_commit, "demo-lib", "parse_header(const char *buf"):
            self.assertNotIn(leaked, text)

        # Balanced detection labels, and the fixed version is shown for the "false" example
        det = [e for e in examples if e["meta"]["task"] == "detection"]
        labels = [json.loads(e["messages"][-1]["content"])["is_vulnerable"] for e in det]
        self.assertEqual(labels.count(True), labels.count(False))
        fixed_ex = next(e for e in det if e["meta"]["version"] == "fixed")
        self.assertIn("if (n > 8)", fixed_ex["messages"][1]["content"])

        # Same prompt text as the evaluation pipeline produces
        from pipeline.task_prompts import build_repair_messages
        rep = next(e for e in examples if e["meta"]["task"] == "repair" and e["meta"]["project"] == "openssl")
        region = bfd._region(bfd.Pair(vulnerable=rep["messages"][1]["content"].split("```c\n")[1].split("\n```")[0] + "\n",
                                      fixed="", commit="", project="openssl", cve=None, cwe="CWE-787",
                                      cve_desc="", file_name="crypto/foo.c", source=""))
        self.assertEqual(build_repair_messages("openssl", [region], cwe="CWE-787"), rep["messages"][:2])
        self.assertTrue(rep["messages"][-1]["content"].startswith("### File: foo.c\n```c\n"))

    def test_split_is_grouped_by_commit(self):
        out = self.tmp / "ft"
        bfd.build([self.input], None, out, ["detection", "repair"], valid_fraction=0.5)
        train = {json.loads(line)["meta"]["commit"] for line in open(out / "train.jsonl")}
        valid = {json.loads(line)["meta"]["commit"] for line in open(out / "valid.jsonl")}
        self.assertTrue(train and valid)
        self.assertFalse(train & valid)
        manifest = json.loads((out / "manifest.json").read_text())
        self.assertEqual(manifest["leakage_check"], "NOT PERFORMED")

    def test_too_long_and_unchanged_pairs_dropped(self):
        long_fn = "int g(void)\n{\n" + "    x++;\n" * 400 + "}\n"
        p = self.tmp / "p2.jsonl"
        p.write_text(json.dumps({"func_before": long_fn, "func_after": long_fn + "\n", "commit_id": "1" * 40}) + "\n"
                     + json.dumps({"func_before": long_fn, "func_after": long_fn.replace("x++", "y++"),
                                   "commit_id": "2" * 40}) + "\n")
        m = bfd.build([p], None, self.tmp / "o", ["repair"], max_lines=300)
        self.assertEqual(m["filtering"]["removed_no_code_change"], 1)
        self.assertEqual(m["filtering"]["removed_too_long"], 1)


class FakeTokenizer:
    """Character-level tokenizer with a ChatML-like template."""

    def apply_chat_template(self, messages, tokenize=False, add_generation_prompt=False):
        text = "".join(f"<s>{m['role']}\n{m['content']}</s>\n" for m in messages)
        return text + ("<s>assistant\n" if add_generation_prompt else "")

    def __call__(self, text, add_special_tokens=False):
        return {"input_ids": [ord(c) for c in text]}


class TestEncodeExample(unittest.TestCase):

    def test_only_answer_is_supervised(self):
        msgs = [{"role": "system", "content": "S"}, {"role": "user", "content": "fix it"},
                {"role": "assistant", "content": "ANSWER"}]
        enc = encode_example(FakeTokenizer(), msgs, max_length=1000)
        supervised = "".join(chr(t) for t, lab in zip(enc["input_ids"], enc["labels"]) if lab != IGNORE_INDEX)
        self.assertEqual(supervised, "ANSWER</s>\n")
        self.assertEqual(len(enc["input_ids"]), len(enc["labels"]))

    def test_too_long_example_is_skipped_not_truncated(self):
        msgs = [{"role": "user", "content": "x" * 50}, {"role": "assistant", "content": "y"}]
        self.assertIsNone(encode_example(FakeTokenizer(), msgs, max_length=20))


if __name__ == "__main__":
    unittest.main()
