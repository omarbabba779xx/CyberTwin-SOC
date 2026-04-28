# Benchmark — Helm cluster (3 backend replicas, production-like envelope)

> Intent: measure HTTP API latency percentiles when the stack runs as a
> **real Kubernetes deployment** behind an ingress — not single-process
> uvicorn on a workstation.
>
> This file is a **reproducible runbook**. Fill the "Reference run" table
> after you execute the checklist on your cluster; commit the numbers in
> the same PR as the infrastructure change they belong to.

## Why this is not in CI by default

Standing up a disposable 3-node Kubernetes cluster on every GitHub
hosted runner would add 8–15 minutes and fragile cloud-specific
credentials. The **default** CI path (`docker compose smoke`, k6 against
`localhost` in ad-hoc benchmarks) keeps feedback under 10 minutes per
push. Production-like numbers are tracked here as a **manual /
release-candidate** artefact.

## Reference hardware profile (fill in when you run)

| Field | Example value |
|-------|---------------|
| Commit SHA | `HEAD` at run time |
| Cloud / on-prem | *(e.g. EKS 1.31, 3 × m6i.large)* |
| Ingress | NGINX + cert-manager |
| Chart values | `deploy/helm/cybertwin-soc/values.yaml` + `values-secure.yaml` |
| `backend.replicas` | `3` |
| Postgres | managed (RDS / Cloud SQL / …) |
| Redis | managed or in-cluster with persistence |
| k6 VUs / duration | identical to local `benchmark-http-k6.md` for comparability |

## Checklist

```bash
# 0. Build & push images tagged with the SHA you are benchmarking
docker build -f Dockerfile.backend  -t ghcr.io/OWNER/cybertwin-soc-backend:bench .
docker push ghcr.io/OWNER/cybertwin-soc-backend:bench

# 1. Deploy with the secure overlay + 3 replicas
helm upgrade --install cybertwin deploy/helm/cybertwin-soc \
  --namespace cybertwin --create-namespace \
  --values deploy/helm/cybertwin-soc/values.yaml \
  --values deploy/helm/cybertwin-soc/values-secure.yaml \
  --set backend.replicas=3 \
  --set backend.image.tag=bench \
  --set frontend.image.tag=bench \
  --set ingress.host=soc.bench.example.com

# 2. Wait for all pods Ready
kubectl -n cybertwin rollout status deployment/cybertwin-soc-backend --timeout=300s

# 3. Port-forward OR use the public DNS entry the ingress created
export BASE_URL=https://soc.bench.example.com
export TOKEN="$(curl -sk -X POST "$BASE_URL/api/auth/login" ... | jq -r .access_token)"

# 4. Run the same k6 script as local HTTP benchmarks
k6 run -e BASE_URL="$BASE_URL" -e CYBERTWIN_TOKEN="$TOKEN" \
       --summary-export=benchmarks/results/k6-helm-cluster.json \
       benchmarks/k6_api.js

# 5. Upload k6-helm-cluster.json as a release artefact (or attach to the PR).
```

## Results table (fill after run)

| Metric | p50 | p95 | p99 | Notes |
|--------|-----|-----|-----|-------|
| GET /api/health | | | | |
| GET /api/auth/me | | | | |
| GET /api/alerts?limit=20 | | | | |
| Aggregate error rate | | | | |

## Known limits

- **Sticky sessions**: WebSockets require session affinity — ensure the Helm
  `ingress.annotations` enables it for `/api/simulation/stream`.
- **Cold Postgres**: First request after rollout may inflate p95 — warm the
  connection pool (`GET /api/health` × 50) before k6 ramp-up.
- **Network RTT**: k6 runners should live **inside the same VPC / region**
  as the cluster to isolate application latency from WAN variance.
