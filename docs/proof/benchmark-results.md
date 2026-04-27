# Benchmark Results — End-to-End Pipeline

> Last manual update: **2026-04-27**.
> Live JSON: [`benchmarks/results/latest-pipeline.json`](../../benchmarks/results/latest-pipeline.json)

## Environment

| Field           | Value                                          |
|-----------------|------------------------------------------------|
| Commit          | latest on `master` at run time                 |
| Host            | Local Windows 10 dev workstation               |
| CPU             | x86_64                                         |
| Python          | 3.12.10                                        |
| Mode            | In-process (no Docker, no HTTP)                |
| Repeats / scen. | 3                                              |
| Tool            | `python -m benchmarks.bench_pipeline`          |

## Results

Each row reports a **full simulation pipeline** end-to-end:
attack engine → telemetry → detection → correlation → scoring → AI report.

| Scenario              | Mean   | Min    | Max    | Stdev  | Events | Logs   | Alerts | Incidents |
|-----------------------|--------|--------|--------|--------|--------|--------|--------|-----------|
| `sc-apt-campaign-001` | 4.652s | 4.412s | 4.793s | 0.209s | 68     | 68     | 8      | 1         |
| `sc-bruteforce-001`   | 12.597s| 12.217s| 12.927s| 0.357s | 4 581  | 4 581  | 12     | 1         |
| `sc-cloud-attack-001` | 4.409s | 4.405s | 4.415s | 0.005s | 82     | 82     | 6      | 1         |

## Read-out

- **Throughput**: brute-force scenario produces **~4.6k events in ~12.6s** end-to-end (≈ 365 EPS *including* detection, correlation, scoring and AI report).
- **Detection latency**: alerts come from the same in-process detection engine that the live `/api/ingest/detect` endpoint uses, so the same throughput applies to ingestion.
- **Stability**: stdev < 0.4s across all scenarios. Pipeline is deterministic given the same seed.

## Caveats (important)

- These numbers are **in-process** and do **not** include HTTP overhead or container start-up time.
- Fully containerised numbers (HTTP latency p50 / p95 / p99 from k6) will land
  in `2026-04-docker-compose.md` once the Docker CI run is green.
- AI Analyst is in **deterministic NLG mode** here (no Ollama call). LLM-mode
  numbers will be added when an Ollama benchmark run is recorded.
- The `sc-bruteforce-001` scenario intentionally generates a high-volume log
  stream (~4.6k events) to exercise the detection ring-buffer; it is **not**
  representative of typical small-scenario load.

## How to reproduce

```bash
python -m benchmarks.bench_pipeline
# Optional environment knobs:
BENCH_REPEATS=10 BENCH_SCENARIOS=11 python -m benchmarks.bench_pipeline
```

Output is written to `benchmarks/results/latest-pipeline.json`.
