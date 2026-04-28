# Contributing to CyberTwin SOC

Thanks for your interest in CyberTwin SOC. This project welcomes contributions
of all sizes, from typo fixes to new detection rules and integrations.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Workflow](#development-workflow)
- [Coding Standards](#coding-standards)
- [Tests](#tests)
- [Commit Conventions](#commit-conventions)
- [Pull Request Checklist](#pull-request-checklist)
- [Areas Where We Need Help](#areas-where-we-need-help)

## Code of Conduct

Be respectful, constructive, and assume good intent. We do not tolerate
harassment in any form. Keep technical disagreements technical.

## Getting Started

```bash
git clone https://github.com/omarbabba779xx/CyberTwin-SOC.git
cd CyberTwin-SOC

# Backend
python -m venv .venv
.venv/Scripts/Activate.ps1   # Windows
# or: source .venv/bin/activate
pip install -r requirements.txt
pip install pytest pytest-asyncio httpx pytest-cov

# Frontend
cd frontend
npm ci
cd ..

# Run tests
python -m pytest tests/ -v
```

For a full Docker setup, see the *Docker Deployment* section of `README.md`.

## Development Workflow

1. **Fork** the repository on GitHub.
2. **Create a feature branch** from `master`:
   ```bash
   git checkout -b feat/short-description
   ```
3. **Make small, focused commits.** One logical change per commit.
4. **Run tests locally** before pushing — see [Tests](#tests).
5. **Open a Pull Request** against `master`. Fill the description with:
   - What problem this solves
   - How to reproduce / test the change
   - Any breaking changes

## Coding Standards

**Python (backend):**

- Python ≥ 3.11
- Format: `black --line-length 120 backend/`
- Lint: `flake8 backend/ --max-line-length=120 --ignore=E501,W503,E402`
- Type hints encouraged, especially for public functions
- Imports always at the top of the file
- Use `logging` (never `print`) and the existing module loggers

**JavaScript / React (frontend):**

- React 18 with hooks (no class components)
- Tailwind CSS for styling
- One component per file under `src/pages/` or `src/components/`
- Avoid prop drilling — colocate state near its consumer

**General:**

- No new files unless strictly necessary
- No emojis in code unless explicitly requested
- Prefer minimal, surgical edits over rewrites
- Public APIs (endpoints) require updated docs in `README.md`

## Tests

The project ships with **253 backend tests**. New features must include tests.

```bash
# Full suite
python -m pytest tests/ -v

# Single file
python -m pytest tests/test_detection.py -v

# With coverage
python -m pytest tests/ --cov=backend --cov-report=term-missing
```

When adding a detection rule, also add a fixture in
`tests/test_detection.py` proving the rule fires on a known-bad event
and stays silent on a benign one.

## Commit Conventions

Use [Conventional Commits](https://www.conventionalcommits.org/):

```
feat:     new user-visible feature
fix:      bug fix
docs:     documentation only
test:     adding or fixing tests
refactor: code change that neither fixes a bug nor adds a feature
chore:    tooling, deps, CI, build
```

Examples:

- `feat: add Kerberoasting detection rule (RULE-047)`
- `fix(soar): use _get_cached_result instead of missing orchestrator method`
- `docs: clarify MITRE coverage definitions in README`

## Pull Request Checklist

Before requesting review, verify:

- [ ] All tests pass: `python -m pytest tests/`
- [ ] No new flake8 errors: `flake8 backend/`
- [ ] `README.md` updated if behavior or endpoints changed
- [ ] `CHANGELOG.md` entry added under `[Unreleased]`
- [ ] No secrets, tokens, or absolute paths committed
- [ ] `git diff` reviewed locally (no debug `print`, no commented-out code)

## Areas Where We Need Help

- **Detection engineering** — new Sigma-style rules, especially for cloud,
  containers, and identity providers (Okta, Entra ID).
- **Connectors** — concrete implementations for Splunk, Sentinel, Elastic,
  Jira, MISP, OpenCTI.
- **Normalization** — OCSF / ECS field mappers for Windows Event, Sysmon,
  AWS CloudTrail.
- **Frontend** — Detection Coverage Center, Gap Analyzer, Case Management
  views (see roadmap in `README.md`).
- **Documentation** — tutorials, screenshots, deployment recipes.

Thank you for contributing.
