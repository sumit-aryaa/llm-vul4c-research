# Re-scoring notes (2026-10-23)

The Qwen2.5-Coder-1.5B outputs in `generations.jsonl` (model `ollama-qwen-1.5b`) are the original run and were **not** regenerated. Everything derived from them was recomputed with the fixed pipeline.

## Why the files were recomputed

1. **Line-ending bug.** The original run used a copy of the benchmark with Windows (CRLF) line endings. When the pipeline put an answer back into the file, it dropped the CRLF and also lost trailing blank lines and spaces. As a result, every candidate counted as "changed", including the `identity` sanity model, which returns the code unchanged (136/136).
2. **CWE labels.** Benchmark labels such as `NVD-CWE-Other` were rejected by the JSON validator. This made 4–8 sanity-model answers "invalid".
3. **Only cppcheck ran.** flawfinder was not installed. The re-score uses cppcheck 2.13 (with `--max-configs=1`) and flawfinder 2.0.20.

## What was regenerated

- `oracle` and `identity` entries in `generations.jsonl`. These are deterministic sanity models; no LLM is involved.
- `evaluations.jsonl`, `report.md`, the CSV files and `summary.json`.

## Not done yet

**The dynamic stage did not run in the original run** (`--no-docker`; 0 calibrated cases). Compile, exploit and test results are therefore still missing, and so is the "security side effects" section. To fill them in, re-run the evaluate stage with Docker:

```bash
python3 pipeline/run_experiment.py --config <config with this experiment_name> --stage evaluate
python3 pipeline/run_experiment.py --config <same config> --stage report
```

The model does not need to be queried again.

# Re-scoring notes (2026-11-10)

The model outputs in `generations.jsonl` are unchanged again. `evaluations.jsonl`, `report.md`, `repair_summary.csv`, `summary.json` and `cases.json` were recomputed with the current pipeline, with the same tools as before (cppcheck 2.13 with `--max-configs=1`, flawfinder 2.0.20).

## Why

1. **Echoed prompt lines.** The Qwen 1.5B model often starts its answer by repeating prompt lines inside the code block (`[BEGIN UNTRUSTED SOURCE CODE]`, `### File: ...`, a second opening fence). The earlier parser took those lines as the answer and replaced the whole function with them. The parser introduced with the Docker pilot (commit `00f7182`) reads the real code. This changes 45 of the 136 Qwen 1.5B candidates.
2. **Blank lines at region edges.** That parser also removed blank lines at the start and end of a region, so `identity` and `oracle` no longer round-tripped on 19 cases. This is fixed; both now round-trip on all 136 cases.
3. **`generation_ok`** is now recomputed at evaluation time with the current parser. Before, it kept the value from generation time.

## Effect on Qwen2.5-Coder-1.5B (136 candidates)

| Metric | Before | Now |
|---|---|---|
| Answer has code for every region | 124 (91.2%) | 129 (94.9%) |
| Patch changes the code | 89 (65.4%) | 68 (50.0%) |
| New high-severity static finding | 5 (3.7%) | 4 (2.9%) |

So in half of the cases the model returns the vulnerable code unchanged. `identity` (0 changed) and `oracle` (136 identical to the fix) are as expected. Detection results did not change.

## File names in 35 prompts

`cases.json` now shows corrected file names for 35 cases (jasper, libtiff, libarchive, libzip, gilcc), for example `jpc_tsfb.c` where it showed `tsfb.c`. The name-extraction fix in `pipeline/case_manager.py` (commit `00f7182`) caused this. The stored model outputs were generated when the prompt heading still showed the shortened name. The code in the prompt was the same. Regenerating would remove this small difference; it has not been done.

## Still not done

The dynamic stage (Docker) has not run: 0 calibrated cases. To add it, run the evaluate stage again without `--no-docker`. The `not_run` records are then evaluated again and replaced; nothing has to be deleted.
