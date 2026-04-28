# Production Deployment Hardening Guide

> Last update: **2026-04-28** · Commit: `d0f4e3f`
> Scope: `docker-compose.yml` (single-host) and `deploy/helm/cybertwin-soc`
> (Kubernetes). This document is the single reference for what changes
> between the developer-friendly defaults and a production deployment.

The repo's defaults (`docker-compose.yml`, `values.yaml`) are tuned for
a developer who clones the repo and wants the stack up in 12 seconds.
Production deployments **must** apply every checklist item below before
exposing the SOC to real data or users.

---

## 1. Required environment variables (no defaults in production)

| Variable | Purpose | Generated how? |
|---|---|---|
| `JWT_SECRET` | HS256 signing key for access + refresh tokens | `openssl rand -hex 64` |
| `AUTH_ADMIN_PASSWORD` | bootstrap admin password | strong, ≥ 24 chars, password manager |
| `AUTH_ANALYST_PASSWORD` | bootstrap analyst password | same |
| `AUTH_VIEWER_PASSWORD` | bootstrap viewer password | same |
| `OIDC_CLIENT_SECRET` | OIDC SSO client secret | from your IdP |
| `DATABASE_URL` | PostgreSQL connection string with TLS | `postgresql+psycopg2://user:pass@host:5432/db?sslmode=require` |
| `REDIS_URL` | Redis connection string with TLS / AUTH | `rediss://:password@host:6380/0` |
| `CONNECTOR_THEHIVE_API_KEY` | TheHive SOAR API key | from TheHive admin UI |
| `CONNECTOR_SPLUNK_TOKEN` | Splunk SIEM token | from Splunk Auth Tokens |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | OpenTelemetry collector endpoint | `https://otel-collector.observability:4317` |

**Validation**: the backend refuses to start in `ENV=production` if
any of `JWT_SECRET`, `AUTH_*_PASSWORD` are missing or below the
minimum-entropy threshold. See `backend/auth/_core.py::_load_jwt_secret`
for the secret-strength gate.

---

## 2. Docker Compose — production checklist

`docker-compose.yml` is fine **for a single-host lab**. For production
on a single host, apply these overlays and changes:

### 2.1. Do not expose backend / frontend / SOAR ports publicly

The default `ports:` clauses bind to every interface. Remove them and
front everything with a reverse proxy:

```yaml
# docker-compose.production.yml (overlay)
services:
  backend:
    ports: []        # was: "8000:8000" — closed in production
    expose: ["8000"] # only the reverse proxy can reach it
  frontend:
    ports: []        # was: "80:8080" — closed in production
    expose: ["8080"]
  thehive:
    ports: []        # was: "9000:9000"
    expose: ["9000"]
  cortex:
    ports: []        # was: "9001:9001"
    expose: ["9001"]
```

Then run:

```bash
docker compose \
  -f docker-compose.yml \
  -f docker-compose.production.yml \
  up -d
```

### 2.2. Front everything with TLS via a reverse proxy

Either Caddy or Traefik handles ACME automatically:

```yaml
# Caddyfile (one-line TLS for the SOC)
soc.example.com {
  reverse_proxy /api/* backend:8000
  reverse_proxy /*     frontend:8080
  encode gzip
  header Strict-Transport-Security "max-age=31536000; includeSubDomains"
  header X-Frame-Options DENY
  header X-Content-Type-Options nosniff
  header Referrer-Policy strict-origin-when-cross-origin
}
```

### 2.3. Secrets — never in `.env`, always via Docker secrets

```yaml
# docker-compose.production.yml
secrets:
  jwt_secret:        { external: true }
  admin_password:    { external: true }
  analyst_password:  { external: true }
  viewer_password:   { external: true }
  oidc_secret:       { external: true }
services:
  backend:
    secrets:
      - jwt_secret
      - admin_password
      - analyst_password
      - viewer_password
      - oidc_secret
    environment:
      JWT_SECRET_FILE:        /run/secrets/jwt_secret
      AUTH_ADMIN_PASSWORD_FILE: /run/secrets/admin_password
```

Bootstrap once with `docker secret create`:

```bash
openssl rand -hex 64 | docker secret create jwt_secret -
```

### 2.4. Network segmentation

```yaml
# docker-compose.production.yml
networks:
  public:   { driver: bridge }
  internal: { driver: bridge, internal: true }   # no external egress
services:
  backend:  { networks: [internal, public] }
  redis:    { networks: [internal] }            # never reachable from outside
  worker:   { networks: [internal] }
  thehive:  { networks: [internal] }
  cortex:   { networks: [internal] }
```

### 2.5. Persistent volumes for state

```yaml
volumes:
  postgres-data: { driver: local }
  redis-data:    { driver: local }
  thehive-data:  { driver: local }
```

Back up `postgres-data` daily with `pg_dump` to an off-host store.

---

## 3. Kubernetes — use `values-secure.yaml`

`deploy/helm/cybertwin-soc/values-secure.yaml` is the production
overlay. Apply it on top of `values.yaml`:

```bash
helm upgrade --install cybertwin deploy/helm/cybertwin-soc \
  --namespace cybertwin --create-namespace \
  --values deploy/helm/cybertwin-soc/values.yaml \
  --values deploy/helm/cybertwin-soc/values-secure.yaml \
  --set ingress.host=soc.example.com
```

What `values-secure.yaml` enables vs. the default `values.yaml`:

| Control | Default (`values.yaml`) | Secure (`values-secure.yaml`) |
|---|---|---|
| `securityContext.readOnlyRootFilesystem` | `false` | **`true`** + `/tmp` emptyDir |
| `seccompProfile` | unset | **`RuntimeDefault`** |
| `networkPolicy.enabled` | `false` | **`true`** + scoped allow rules |
| `podDisruptionBudget` | none | `minAvailable: 2` |
| `podAntiAffinity` | none | per-host topology spread |
| Backend replicas | 2 | 3 |
| Probes (startup / liveness / readiness) | basic | full triple with tuned thresholds |
| Ingress HSTS / SSL-redirect / rate-limit | not annotated | enforced via `nginx.ingress.kubernetes.io/*` |
| OTel sampling | unset | parentbased\_traceidratio @ 10 % |

### 3.1. Secrets — use ExternalSecrets / SealedSecrets

`values-secure.yaml` references `existingSecret: cybertwin-secrets`.
Create it via your secret-management operator, NOT manually:

```yaml
# Example — External Secrets Operator pulling from AWS Secrets Manager
apiVersion: external-secrets.io/v1beta1
kind: ExternalSecret
metadata:
  name: cybertwin-secrets
  namespace: cybertwin
spec:
  refreshInterval: 1h
  secretStoreRef:
    name: aws-secrets
    kind: ClusterSecretStore
  target:
    name: cybertwin-secrets
  data:
    - secretKey: JWT_SECRET
      remoteRef: { key: cybertwin/prod/jwt_secret }
    - secretKey: AUTH_ADMIN_PASSWORD
      remoteRef: { key: cybertwin/prod/admin_password }
    # ... etc for every required env var
```

### 3.2. Postgres + Redis as managed services

The chart's bundled Redis is fine for development. **Production should
use a managed Postgres** (RDS, Cloud SQL, Neon …) and a managed Redis
(ElastiCache, MemoryStore …) with TLS, daily backups, and read
replicas. Set `redis.enabled: false` in `values-secure.yaml` overrides
when migrating to managed services.

---

## 4. Verify the production posture

After deploying with `values-secure.yaml`, run this checklist:

```bash
# 1. NetworkPolicy is in effect
kubectl -n cybertwin get networkpolicy
# expect: cybertwin-default-deny + cybertwin-allow-* rules

# 2. Pods run with read-only root FS
kubectl -n cybertwin get pod -l app=backend -o json | \
  jq '.items[].spec.containers[0].securityContext'
# expect: readOnlyRootFilesystem: true, runAsNonRoot: true,
#         allowPrivilegeEscalation: false, capabilities.drop: ["ALL"]

# 3. PodDisruptionBudget is honoured
kubectl -n cybertwin get pdb
# expect: cybertwin-backend  ALLOWED DISRUPTIONS = 1 (3 replicas, minAvailable=2)

# 4. Ingress redirects HTTP to HTTPS
curl -sI http://soc.example.com | head -1
# expect: HTTP/1.1 308 Permanent Redirect

# 5. Probes fire correctly
kubectl -n cybertwin describe pod -l app=backend | grep -E "Liveness|Readiness|Startup"
# expect: triple probes configured with the documented thresholds

# 6. CPU + memory limits applied
kubectl -n cybertwin get pod -l app=backend \
  -o jsonpath='{.items[0].spec.containers[0].resources}'
# expect: requests: 500m / 512Mi, limits: 1500m / 1.5Gi
```

---

## 5. What is intentionally *not* production-default

For transparency, here is what `values.yaml` keeps at developer-friendly
defaults that `values-secure.yaml` then hardens:

- `readOnlyRootFilesystem: false` in `values.yaml` because some local
  dev workflows mount notebooks for ad-hoc benchmarking.
- `networkPolicy.enabled: false` in `values.yaml` because kind / minikube
  on macOS occasionally ships without a CNI that enforces NetworkPolicy.
  Production clusters with Calico / Cilium / VPC-CNI are the only target
  for the secure overlay.

This separation is deliberate and documented in the chart's
`values.yaml` header. The README already directs operators to
`values-secure.yaml` for production.
