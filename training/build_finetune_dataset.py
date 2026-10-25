"""Build a leak-free fine-tuning dataset in the evaluation pipeline's prompt format.

Input: vulnerable/fixed function pairs from a large C/C++ vulnerability dataset
(PrimeVul paired files, MegaVul, or any JSONL with the same information).
Output: chat-format SFT examples whose prompts are produced by the SAME
functions the evaluation uses (pipeline/task_prompts.py), so the model learns
exactly the format it is tested on:

  * detection on the vulnerable version -> {"is_vulnerable": true,  "cwe": ...}
  * detection on the fixed version      -> {"is_vulnerable": false, "cwe": null}
  * repair of the vulnerable version    -> fixed function in a fenced code block

Leakage control against the test benchmark (Vul4C). A training pair is removed if:
  1. its CVE ID is a Vul4C CVE,
  2. its commit hash appears in Vul4C metadata (vulnerable or fixing commit),
  3. it comes from a Vul4C project (on by default; --keep-test-projects to disable),
  4. its vulnerable or fixed function is identical (ignoring whitespace/comments)
     to any Vul4C function region.
Every removal is counted per reason in manifest.json, which belongs in the paper.

Splitting is grouped by commit, so the two versions of one fix and all functions
of one commit always land in the same split.

Usage:
  python3 training/build_finetune_dataset.py \\
      --input primevul_train_paired.jsonl primevul_valid_paired.jsonl \\
      --vul4c-root /path/to/SoK/Vul4C-Benchmark \\
      --out data/finetune
"""

import argparse
from collections import Counter, defaultdict
from dataclasses import dataclass, field
import hashlib
import json
from pathlib import Path
import random
import re
import sys
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from pipeline.patch_manager import CodeRegion, normalize_code  # noqa: E402
from pipeline.task_prompts import (  # noqa: E402
    build_detection_messages, build_repair_messages, oracle_repair_answer,
)

# Field-name aliases across PrimeVul / MegaVul / other dumps.
ALIASES = {
    "func": ["func", "function", "code", "func_before_or_after"],
    "func_before": ["func_before", "vulnerable_func", "before", "old_func"],
    "func_after": ["func_after", "fixed_func", "after", "new_func", "patched_func"],
    "target": ["target", "label", "vul", "is_vulnerable"],
    "commit": ["commit_id", "commit_hash", "commit", "hash"],
    "project": ["project", "repo_name", "repo", "project_name"],
    "cve": ["cve", "cve_id", "CVE ID", "cve_ids"],
    "cwe": ["cwe", "cwe_ids", "cwe_id", "CWE ID"],
    "cve_desc": ["cve_desc", "description", "cve_description", "nvd_desc"],
    "file_name": ["file_name", "file_path", "file", "filename"],
}

HEX40 = re.compile(r"\b[0-9a-f]{40}\b", re.I)
CVE_RE = re.compile(r"CVE-\d{4}-\d+", re.I)
CWE_RE = re.compile(r"^CWE-\d+$", re.I)
FUNC_NAME_RE = re.compile(r"([A-Za-z_]\w*)\s*\(")

BENIGN_REASONING = "No security vulnerability is evident in this code; the relevant inputs are handled safely."


def pick(rec: Dict[str, Any], key: str) -> Any:
    for name in ALIASES[key]:
        if name in rec and rec[name] not in (None, ""):
            return rec[name]
    return None


def first_cve(value: Any) -> Optional[str]:
    if value is None:
        return None
    m = CVE_RE.search(json.dumps(value) if not isinstance(value, str) else value)
    return m.group(0).upper() if m else None


def first_cwe(value: Any) -> Optional[str]:
    items = value if isinstance(value, list) else [value]
    for item in items:
        if isinstance(item, str) and CWE_RE.match(item.strip()):
            return item.strip().upper()
    return None


def func_name(code: str) -> str:
    head = code.split("{", 1)[0]
    names = FUNC_NAME_RE.findall(head)
    return names[-1] if names else ""


def norm_project(name: Optional[str]) -> str:
    return re.sub(r"[^a-z0-9]", "", (name or "").lower())


@dataclass
class Pair:
    vulnerable: str
    fixed: str
    commit: str
    project: str
    cve: Optional[str]
    cwe: Optional[str]
    cve_desc: str
    file_name: str
    source: str
    meta: Dict[str, Any] = field(default_factory=dict)


# --------------------------------------------------------------------------- #
# Loading
# --------------------------------------------------------------------------- #

def read_jsonl(path: Path) -> Iterable[Dict[str, Any]]:
    opener = open
    if path.suffix == ".gz":
        import gzip
        opener = gzip.open  # type: ignore[assignment]
    with opener(path, "rt", encoding="utf-8") as fh:
        first = fh.read(1)
        fh.seek(0)
        if first == "[":  # a JSON array instead of JSONL
            yield from json.load(fh)
            return
        for line in fh:
            line = line.strip()
            if line:
                yield json.loads(line)


def load_pairs(paths: List[Path], stats: Counter) -> List[Pair]:
    """Accepts before/after records, or labelled single-function records grouped by commit."""
    pairs: List[Pair] = []
    singles: Dict[Tuple[str, str, str], Dict[int, Dict[str, Any]]] = defaultdict(dict)
    order: List[Tuple[str, str, str]] = []
    for path in paths:
        for rec in read_jsonl(path):
            stats["input_records"] += 1
            commit = str(pick(rec, "commit") or "")
            common = dict(
                commit=commit, project=str(pick(rec, "project") or ""),
                cve=first_cve(pick(rec, "cve")), cwe=first_cwe(pick(rec, "cwe")),
                cve_desc=str(pick(rec, "cve_desc") or "").strip(),
                file_name=str(pick(rec, "file_name") or ""), source=path.name,
            )
            before, after = pick(rec, "func_before"), pick(rec, "func_after")
            if before and after:
                pairs.append(Pair(vulnerable=before, fixed=after, **common))
                continue
            code, target = pick(rec, "func"), pick(rec, "target")
            if code is None or target is None:
                stats["skipped_unrecognised_record"] += 1
                continue
            key = (commit, common["file_name"], func_name(code))
            label = 1 if str(target).lower() in ("1", "true") else 0
            if key not in singles:
                order.append(key)
            if label in singles[key]:
                stats["skipped_duplicate_in_pair_key"] += 1
                continue
            singles[key][label] = {"code": code, **common}
    for key in order:
        both = singles[key]
        if 1 in both and 0 in both:
            v, f = both[1], both[0]
            info = {k: v.get(k) or f.get(k) for k in ("commit", "project", "cve", "cwe", "cve_desc", "file_name", "source")}
            pairs.append(Pair(vulnerable=v["code"], fixed=f["code"], **info))
        else:
            stats["skipped_unpaired_function"] += 1
    return pairs


# --------------------------------------------------------------------------- #
# Test-set (Vul4C) fingerprints
# --------------------------------------------------------------------------- #

@dataclass
class TestFingerprint:
    cves: Set[str] = field(default_factory=set)
    commits: Set[str] = field(default_factory=set)
    projects: Set[str] = field(default_factory=set)
    code: Set[str] = field(default_factory=set)


def vul4c_fingerprint(vul4c_root: Path, dataset_json: Optional[Path] = None) -> TestFingerprint:
    from pipeline.run_experiment import DEFAULTS, _merge, prepare_cases

    fp = TestFingerprint()
    cfg = _merge(DEFAULTS, {"benchmark_root": str(vul4c_root), "cases": [],
                            "vul4c_dataset_json": str(dataset_json) if dataset_json else None,
                            "context": {"max_total_region_lines": 10 ** 9}})
    cases, _ = prepare_cases(cfg)
    for c in cases:
        fp.cves.add(c.cve_id.upper())
        fp.projects.add(norm_project(c.project))
        for r in c.regions:
            for code in (r.old_code, r.new_code):
                fp.code.add(hashlib.sha1(normalize_code(code).encode()).hexdigest())
    for case_dir in vul4c_root.glob("*/*"):
        if case_dir.is_dir():
            fp.projects.add(norm_project(case_dir.parent.name))
            m = CVE_RE.search(case_dir.name)
            if m:
                fp.cves.add(m.group(0).upper())
    ds_path = dataset_json or vul4c_root.parent / "Vul4C_Src" / "Vul4C.json"
    if ds_path.exists():
        data = json.loads(ds_path.read_text(encoding="utf-8"))
        for cve, info in data.items():
            fp.cves.add(cve.upper())
            blob = json.dumps(info)
            fp.commits.update(h.lower() for h in HEX40.findall(blob))
            for url in re.findall(r"github\.com/([\w.-]+)/([\w.-]+?)(?:\.git)?[\s\"/]", blob):
                fp.projects.add(norm_project(url[1]))
    fp.projects.discard("")
    return fp


def project_overlaps(project: str, test_projects: Set[str]) -> bool:
    p = norm_project(project)
    if not p:
        return False
    for t in test_projects:
        if len(t) >= 4 and len(p) >= 4 and (t in p or p in t):
            return True
    return False


# --------------------------------------------------------------------------- #
# Conversion
# --------------------------------------------------------------------------- #

def _region(pair: Pair) -> CodeRegion:
    name = Path(pair.file_name).name if pair.file_name else "code.c"
    vul, fix = pair.vulnerable, pair.fixed
    vul = vul if vul.endswith("\n") else vul + "\n"
    fix = fix if fix.endswith("\n") else fix + "\n"
    return CodeRegion(file_name=name, old_start=0, old_end=vul.count("\n"), new_start=0,
                      new_end=fix.count("\n"), old_code=vul, new_code=fix, kind="function")


def to_examples(pair: Pair, tasks: List[str], cwe_hint: bool) -> List[Dict[str, Any]]:
    region = _region(pair)
    project = pair.project or "unknown"
    out = []
    meta = {"commit": pair.commit, "project": pair.project, "cve": pair.cve, "cwe": pair.cwe, "source": pair.source}
    if "detection" in tasks:
        reasoning = pair.cve_desc[:600] if pair.cve_desc else "The code contains a security vulnerability."
        for version, label in (("vulnerable", True), ("fixed", False)):
            answer = json.dumps({
                "is_vulnerable": label,
                "cwe": pair.cwe if label else None,
                "evidence": None,
                "reasoning": reasoning if label else BENIGN_REASONING,
            })
            msgs = build_detection_messages(project, [region], use_new=not label)
            out.append({"messages": msgs + [{"role": "assistant", "content": answer}],
                        "meta": dict(meta, task="detection", version=version)})
    if "repair" in tasks:
        msgs = build_repair_messages(project, [region], cwe=pair.cwe if cwe_hint else None)
        out.append({"messages": msgs + [{"role": "assistant", "content": oracle_repair_answer([region])}],
                    "meta": dict(meta, task="repair", version="vulnerable")})
    return out


def split_of(commit: str, project: str, valid_fraction: float, seed: int) -> str:
    key = commit or project or "none"
    h = int(hashlib.sha256(f"{seed}:{key}".encode()).hexdigest()[:8], 16) / 0xFFFFFFFF
    return "valid" if h < valid_fraction else "train"


def build(paths: List[Path], fp: Optional[TestFingerprint], out_dir: Path, tasks: List[str],
          max_lines: int = 300, valid_fraction: float = 0.05, seed: int = 42,
          exclude_projects: bool = True, cwe_hint: bool = True,
          max_pairs: Optional[int] = None) -> Dict[str, Any]:
    stats: Counter = Counter()
    pairs = load_pairs(paths, stats)
    stats["pairs_loaded"] = len(pairs)
    kept: List[Pair] = []
    removed_projects: Counter = Counter()
    seen: Set[str] = set()
    for p in pairs:
        n_v, n_f = normalize_code(p.vulnerable), normalize_code(p.fixed)
        if n_v == n_f:
            stats["removed_no_code_change"] += 1
            continue
        dedup = hashlib.sha1((n_v + "\0" + n_f).encode()).hexdigest()
        if dedup in seen:
            stats["removed_duplicate_pair"] += 1
            continue
        if max(p.vulnerable.count("\n"), p.fixed.count("\n")) + 1 > max_lines:
            stats["removed_too_long"] += 1
            continue
        if fp is not None:
            if p.cve and p.cve.upper() in fp.cves:
                stats["removed_leak_cve"] += 1
                continue
            if p.commit and p.commit.lower() in fp.commits:
                stats["removed_leak_commit"] += 1
                continue
            if exclude_projects and project_overlaps(p.project, fp.projects):
                stats["removed_leak_project"] += 1
                removed_projects[p.project] += 1
                continue
            if any(hashlib.sha1(x.encode()).hexdigest() in fp.code for x in (n_v, n_f)):
                stats["removed_leak_identical_code"] += 1
                continue
        seen.add(dedup)
        kept.append(p)

    rng = random.Random(seed)
    rng.shuffle(kept)
    if max_pairs:
        kept = kept[:max_pairs]
    out_dir.mkdir(parents=True, exist_ok=True)
    counts: Counter = Counter()
    cwes: Counter = Counter()
    with open(out_dir / "train.jsonl", "w", encoding="utf-8") as tr, \
            open(out_dir / "valid.jsonl", "w", encoding="utf-8") as va:
        for p in kept:
            split = split_of(p.commit, p.project, valid_fraction, seed)
            cwes[p.cwe or "unknown"] += 1
            for ex in to_examples(p, tasks, cwe_hint):
                (va if split == "valid" else tr).write(json.dumps(ex, ensure_ascii=False) + "\n")
                counts[f"{split}_{ex['meta']['task']}"] += 1
            counts[f"{split}_pairs"] += 1

    manifest = {
        "inputs": [str(p) for p in paths],
        "tasks": tasks,
        "settings": {"max_lines": max_lines, "valid_fraction": valid_fraction, "seed": seed,
                     "exclude_test_projects": exclude_projects, "cwe_hint": cwe_hint, "max_pairs": max_pairs},
        "leakage_check": "vul4c" if fp is not None else "NOT PERFORMED",
        "test_fingerprint": None if fp is None else {
            "cves": len(fp.cves), "commits": len(fp.commits), "projects": sorted(fp.projects),
            "code_fingerprints": len(fp.code)},
        "filtering": dict(sorted(stats.items())),
        "removed_projects_top": removed_projects.most_common(30),
        "output": dict(sorted(counts.items())),
        "cwe_distribution_top": cwes.most_common(25),
    }
    (out_dir / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return manifest


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--input", nargs="+", required=True, help="JSONL/JSON(.gz) files with function pairs")
    ap.add_argument("--vul4c-root", help="Vul4C-Benchmark folder (test set) for leakage removal")
    ap.add_argument("--vul4c-dataset-json", help="Vul4C_Src/Vul4C.json (default: next to the benchmark)")
    ap.add_argument("--no-leakage-check", action="store_true", help="Skip the test-set check (not for papers)")
    ap.add_argument("--keep-test-projects", action="store_true",
                    help="Keep pairs from projects that also appear in Vul4C (CVE/commit/code checks still apply)")
    ap.add_argument("--out", default="data/finetune")
    ap.add_argument("--tasks", nargs="+", choices=["detection", "repair"], default=["detection", "repair"])
    ap.add_argument("--max-lines", type=int, default=300, help="Drop functions longer than this (eval region cap)")
    ap.add_argument("--valid-fraction", type=float, default=0.05)
    ap.add_argument("--max-pairs", type=int, help="Cap the number of pairs (e.g. for a quick first run)")
    ap.add_argument("--no-cwe-hint", action="store_true", help="Omit the CWE hint in repair prompts")
    ap.add_argument("--seed", type=int, default=42)
    args = ap.parse_args(argv)

    fp = None
    if not args.no_leakage_check:
        if not args.vul4c_root:
            ap.error("--vul4c-root is required (or pass --no-leakage-check)")
        fp = vul4c_fingerprint(Path(args.vul4c_root),
                               Path(args.vul4c_dataset_json) if args.vul4c_dataset_json else None)
    manifest = build([Path(p) for p in args.input], fp, Path(args.out), args.tasks,
                     args.max_lines, args.valid_fraction, args.seed,
                     exclude_projects=not args.keep_test_projects, cwe_hint=not args.no_cwe_hint,
                     max_pairs=args.max_pairs)
    print(json.dumps({k: manifest[k] for k in ("leakage_check", "filtering", "output")}, indent=2))
    print(f"Wrote {args.out}/train.jsonl, valid.jsonl and manifest.json")
    return 0


if __name__ == "__main__":
    sys.exit(main())
