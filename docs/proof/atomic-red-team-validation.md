# Atomic Red Team Metadata Validation

CyberTwin SOC uses Atomic Red Team as a local metadata catalog only. The API
and frontend expose technique IDs, platforms, executor names, dependencies,
input argument names, and command-free validation plans. Atomic command bodies
and cleanup command bodies are not exposed by default and are not executed.

## Latest Upstream Check

Validation date: 2026-05-02

Upstream repository: `redcanaryco/atomic-red-team`

Fresh clone status:

| Field | Value |
| --- | --- |
| Commit | `113f30c97c33` |
| Commit date | `2026-05-01T23:10:14-04:00` |
| Subject | `Attack v19 migration (#3329)` |
| Techniques indexed | 331 |
| Parser schema | `atomic-red-team-yaml` |
| Compatibility | `ATT&CK v19 metadata-compatible` |

Command used:

```bash
python scripts/validate_atomic_catalog.py --path /path/to/atomic-red-team --limit 80
```

Observed result:

| Check | Result |
| --- | --- |
| Parsed sample | 80 techniques |
| Parser failures | 0 |
| Missing validation plans | 0 |
| Command leakage | 0 |

## Safety Boundary

- `backend/mitre/atomic_red_team.py` omits `command` and `cleanup_command`
  fields unless an internal caller explicitly asks for `include_commands=True`.
- API routes call the safe default and require `view_results`.
- The React page displays metadata and validation planning artifacts only.
- CyberTwin does not run Atomic tests. Execution remains an external lab
  responsibility with change approval, isolation, telemetry readiness, and
  rollback planning.
