# CyberTwin SOC - Benchmarks

Real measurements over the synthetic API. The goal is **honest** numbers
that you reproduce on your own hardware.

## Targets (initial)

| Metric                         | Target           |
| ------------------------------ | ---------------- |
| API p95 latency                | < 500 ms         |
| Standard simulation duration   | < 10 s           |
| Detection latency p95          | < 3 s            |
| Initial ingestion throughput   | 1,000 events/s   |
| Future enterprise target       | 10,000 events/s  |
| Dashboard first paint          | < 3 s            |

## Tools shipped

- `k6_api_test.js`        - HTTP load over /api/health, /api/ingest/event
- `locust_ingestion.py`   - Python-based ingestion stress test

## How to run

### k6 (HTTP, multi-stage ramp)

```bash
# Install: https://k6.io/docs/get-started/installation/
k6 run benchmarks/k6_api_test.js \
  -e BASE=http://localhost:8000 \
  -e TOKEN="$JWT_TOKEN"
```

Generates a CSV summary you can plot in Grafana or compare across runs.

### Locust (ingestion stress)

```bash
pip install locust
locust -f benchmarks/locust_ingestion.py \
       --host=http://localhost:8000 \
       --users 100 --spawn-rate 10 --run-time 1m \
       --headless
```

## Reading results

The `cybertwin_api_request_duration_seconds` Prometheus histogram
(exposed at `/api/metrics`) gives you per-endpoint p50/p95/p99 with no
extra tooling required.

Sample PromQL:

```
histogram_quantile(0.95,
  sum(rate(cybertwin_api_request_duration_seconds_bucket[5m]))
  by (le, path_template))
```
