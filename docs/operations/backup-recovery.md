# CyberTwin SOC — Backup & Recovery Runbook

## 1. Automated Backup (cron)

Add a cron entry for the service account that runs CyberTwin:

```bash
# Daily at 02:00 UTC — keep DATABASE_URL and REDIS_* in the environment
0 2 * * * /opt/cybertwin/scripts/backup.sh /var/backups/cybertwin/$(date +\%Y\%m\%d_\%H\%M\%S) >> /var/log/cybertwin-backup.log 2>&1
```

Verify the job is registered:

```bash
crontab -l | grep cybertwin
```

## 2. Manual Backup

```bash
# Ensure env vars are loaded
source /opt/cybertwin/.env

# Run with a custom output directory (optional)
./scripts/backup.sh /tmp/cybertwin-manual-backup

# The script prints the resulting .tar.gz path on success
```

The archive contains:

| Path inside archive        | Content                          |
|----------------------------|----------------------------------|
| `staging/postgres.sql`     | Full PostgreSQL dump (`pg_dump`)  |
| `staging/redis-dump.rdb`   | Redis point-in-time snapshot      |
| `staging/env.bak`          | `.env` configuration              |
| `staging/scenarios/*.json` | Attack-scenario definitions       |

## 3. Recovery Procedure

### 3.1 PostgreSQL Restore

```bash
# Extract the archive
tar xzf /var/backups/cybertwin/20260101_020000.tar.gz -C /tmp/restore

# Restore into the target database
psql "$DATABASE_URL" < /tmp/restore/staging/postgres.sql
```

For a full cluster restore (drop + recreate):

```bash
dropdb cybertwin          # WARNING: destructive
createdb cybertwin
psql cybertwin < /tmp/restore/staging/postgres.sql
```

### 3.2 Redis Restore

```bash
# Stop Redis
sudo systemctl stop redis

# Replace the dump file
sudo cp /tmp/restore/staging/redis-dump.rdb /var/lib/redis/dump.rdb
sudo chown redis:redis /var/lib/redis/dump.rdb

# Start Redis — it will reload from the dump
sudo systemctl start redis
```

### 3.3 Configuration & Scenarios

```bash
cp /tmp/restore/staging/env.bak /opt/cybertwin/.env
cp /tmp/restore/staging/scenarios/*.json /opt/cybertwin/scenarios/
```

Restart the application after restoring configuration:

```bash
sudo systemctl restart cybertwin-api cybertwin-worker
```

## 4. Verification Steps

After every restore, run through this checklist:

1. **Database connectivity**
   ```bash
   curl -s http://localhost:8000/api/health/deep | jq .checks.database
   # Expected: "ok"
   ```

2. **Redis connectivity**
   ```bash
   redis-cli -h 127.0.0.1 PING
   # Expected: PONG
   ```

3. **Row counts** — compare against the pre-backup counts recorded in the backup log:
   ```bash
   psql "$DATABASE_URL" -c "SELECT count(*) FROM security_events;"
   psql "$DATABASE_URL" -c "SELECT count(*) FROM audit_log_v2;"
   ```

4. **Scenario integrity** — confirm scenarios load without errors:
   ```bash
   curl -s http://localhost:8000/api/scenarios | jq '.total'
   ```

5. **Smoke-test a simulation run** to confirm end-to-end flow.

## 5. Retention Recommendations

| Data class       | Recommended retention | Rationale                                |
|------------------|-----------------------|------------------------------------------|
| Security events  | 90 days (default)     | Configurable via `DATA_RETENTION_DAYS`   |
| Audit log        | 365 days              | Compliance / forensic investigations     |
| Simulation runs  | Indefinite            | Lightweight; valuable for trend analysis |
| Backups on disk  | 30 days rolling       | Disk-space management                    |

Use the `data_retention` background job to enforce event/audit purge automatically:

```bash
# Enqueue via API
curl -X POST http://localhost:8000/api/tasks \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"task_name": "data_retention"}'
```

For backup rotation, add a cleanup cron:

```bash
# Keep the last 30 backups
0 3 * * * find /var/backups/cybertwin -name '*.tar.gz' -mtime +30 -delete
```
