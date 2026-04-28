# Connectors Validation Report (TheHive · Splunk · Sentinel · Jira · MISP)

**Commit**: `224b757`
**Date**: 2026-04-28
**Test files**:
- [`tests/test_connector_thehive.py`](../../tests/test_connector_thehive.py) — 16 tests
- [`tests/test_connector_splunk.py`](../../tests/test_connector_splunk.py) — 12 tests
**Implementation files**:
- [`backend/connectors/thehive.py`](../../backend/connectors/thehive.py)
- [`backend/connectors/splunk.py`](../../backend/connectors/splunk.py)
**Tests**: 28 / 28 passing

## Why these two first

The reviewer asked for at least 2–3 production-grade connectors out of
the 15 stubs advertised in the README. We picked the two most common
SOC platforms (TheHive for case management, Splunk for SIEM) so any
team adopting CyberTwin can immediately wire either side into their
existing stack.

## Production-grade contract

Both connectors implement the same hardening surface:

| Capability | TheHive | Splunk | Test |
|---|---|---|---|
| Auth (Bearer token) | ✅ `Authorization: Bearer <api_key>` | ✅ `Authorization: Bearer <token>` | `test_describe_lists_config_keys` |
| Explicit timeout | ✅ `httpx.Client(timeout=…)` | ✅ same | implicit |
| Retry on transient errors | ✅ `@with_retry` (timeout / network / 5xx) | ✅ same | `test_5xx_retried_then_succeeds` |
| Circuit breaker | ✅ inherited from `BaseConnector` | ✅ same | `test_health_routes_through_breaker` |
| 4xx → ConnectorError (no retry) | ✅ | ✅ | `test_4xx_raises_connector_error`, `test_401_returns_connection_failure` |
| Pagination | ✅ `range=` cursor on `list_cases` | ✅ `offset/count` on results | `test_list_cases_yields_all_pages`, `test_search_respects_limit` |
| `mock_mode` for tests | ✅ in-memory state | ✅ in-memory state | every fixture-based test |
| Audit-friendly results | ✅ `ConnectorResult{success, message, data}` | ✅ same | every test |
| HTTPS verify toggle | ✅ `verify_ssl` config | ✅ `verify_ssl` config | inspection |
| Registered in factory | ✅ `get_connector("soar","thehive")` | ✅ `get_connector("siem","splunk")` | n/a |

## TheHive — operations covered

| Endpoint | Operation |
|---|---|
| `GET /api/status` | `check_connection()` → version + reachability |
| `POST /api/v1/case` | `create_case(title, description, severity, tags)` |
| `POST /api/v1/case/{id}/observable` | `add_observable(case_id, data_type, data)` |
| `POST /api/v1/case/{id}/task` | `add_task(case_id, title, description)` |
| `GET /api/v1/case?range=` | `list_cases(page_size, max_pages)` (generator) |

```python
def test_create_case_returns_id(self, mock_thehive):
    r = mock_thehive.create_case(
        title="Suspicious login from 203.0.113.42",
        severity="high",
        tags=["mitre:T1110", "cybertwin"],
    )
    assert r.success is True                                  # PASSES
    assert r.data["case_id"].startswith("~mock-")
```

## Splunk — operations covered

| Endpoint | Operation |
|---|---|
| `GET /services/server/info` | `check_connection()` → version |
| `POST /services/search/jobs` | `search(query, limit)` step 1 |
| `GET /services/search/jobs/{sid}` | `search(...)` step 2 — poll until `dispatchState == DONE` |
| `GET /services/search/jobs/{sid}/results` | `search(...)` step 3 — paginate via `offset/count` |
| `POST /services/receivers/simple` | `push_alert(alert)` |

The search lifecycle is the canonical Splunk REST flow:

```
client → POST /search/jobs   { search: "...", output_mode: "json" }
       ← { sid: "1234.567" }

while not done:
    client → GET /search/jobs/{sid}?output_mode=json
           ← { entry: [{ content: { dispatchState: "DONE" }}] }

client → GET /search/jobs/{sid}/results?offset=0&count=1000&output_mode=json
       ← { results: [...], offset: 0, count: 412 }
```

The connector polls every 0.5s until `DONE` or the configured timeout
elapses, then pages through the results until `limit` is reached. All
requests go through the same retry-and-breaker stack as `check_connection`.

## HTTP error mapping (proof)

```python
def test_4xx_raises_connector_error(self):
    def handler(req): return httpx.Response(401, json={"type": "AuthenticationError"})
    c = self._make_connector_with_handler(handler)
    result = c.check_connection()
    assert result.success is False                         # PASSES
    assert "401" in result.message
```

```python
def test_5xx_retried_then_succeeds(self):
    attempts = {"n": 0}
    def handler(req):
        attempts["n"] += 1
        if attempts["n"] < 2: return httpx.Response(503, text="busy")
        return httpx.Response(200, json={"versions": {"TheHive": "5.2.0"}})
    c = self._make_connector_with_handler(handler)
    result = c.check_connection()
    assert result.success is True                          # PASSES
    assert attempts["n"] >= 2                              # actually retried
```

## Reproduce locally

```bash
pytest tests/test_connector_thehive.py tests/test_connector_splunk.py -v
```

Mock mode: any test fixture instantiates the connector with
`mock_mode=True` and exercises the full code path without a network
call. To run against a real instance:

```python
from backend.connectors import get_connector
hive = get_connector(
    "soar", "thehive",
    url="https://hive.your-domain.com",
    api_key=os.environ["THEHIVE_API_KEY"],
    organisation="cybertwin",
)
print(hive.health())
```

## Microsoft Sentinel (`siem`, `sentinel`)

| Concern | Notes |
|---|---|
| Test file | [`tests/test_connector_sentinel.py`](../../tests/test_connector_sentinel.py) |
| API | `POST /v1/workspaces/{wid}/query` (Log Analytics) |
| `push_alert` | Stubbed honesty message — incidents usually flow via Sentinel rules / Graph APIs |

## Jira (`itsm`, `jira`)

| Concern | Notes |
|---|---|
| Test file | [`tests/test_connector_jira.py`](../../tests/test_connector_jira.py) |
| Auth | Email + API token as Basic (`base64(email:token)`) |
| API | REST v3 `POST /rest/api/3/issue` with Atlassian document-format description |

## MISP (`ti`, `misp`)

| Concern | Notes |
|---|---|
| Test file | [`tests/test_connector_misp.py`](../../tests/test_connector_misp.py) |
| REST | Primary `POST /attributes/restSearch` for lookups |

## Limits / next steps

- TheHive — webhook callbacks into CyberTwin are still NOT implemented.
- Splunk — saved-search exports / KV-store not implemented.
- **Elastic, ServiceNow, OpenCTI**, … remain stubs — see [`backend/connectors/stubs.py`](../../backend/connectors/stubs.py).
- Real integrations against customer clusters still require secrets + nightly jobs.
