# Re-scoring notes (2026-10-24)

The Qwen2.5-Coder-7B outputs in `generations.jsonl` (model `ollama-qwen-7b`) are the original run and were **not** regenerated.

The original sanity-model outputs and most evaluations were produced on 2026-10-22, before the line-ending fix in commit `53e08bd` (see `../qwen_1.5b_benchmark/RESCORE_NOTES.md`). As a result, `identity` counted as "changed" in 136 of 136 cases. To correct this:

- the `oracle` and `identity` sanity outputs were regenerated (deterministic; no LLM involved);
- `evaluations.jsonl`, `report.md`, the CSV files and `summary.json` were recomputed with cppcheck 2.13 (`--max-configs=1`) and flawfinder 2.0.20.

`../comparison_1.5b_vs_7b/` was rebuilt from the two re-scored runs. Before that, it still showed the pre-fix 1.5B numbers.

## Known gaps

- **9 of 136 repair requests failed** with `LLMClientError: ... timed out`, because the Ollama 7B model was slow and the default limit is 180 s. They count as "not generated". `config/experiment.json` now sets `"timeout_seconds": 600` for this model. Re-running `--stage generate` retries only the failed requests.
- **The dynamic stage (Docker) did not run** (0 calibrated cases), so compile, exploit and test results are still missing.
