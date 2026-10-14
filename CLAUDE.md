# CLAUDE.md

Working notes for anyone (human or AI) editing this repo. Read this before
changing rules, fixtures, or docs.

## What this repo is

A personal detection engineering lab: Sigma rules for Windows attack
techniques, each mapped to MITRE ATT&CK and checked by a test harness that
replays exported Windows event logs against the rule. It is linked from a
resume, so every claim in it has to be something a reviewer can verify in a
few minutes by cloning and running `pytest`.

## Non-negotiable rules

1. **Never fabricate telemetry.** Generated sample data lives only under
   `fixtures/synthetic/`, carries `"synthetic": true` in its metadata, and is
   excluded from every headline metric. Only events exported from the real
   lab count. The tests enforce the folder/flag pairing.
2. **Every number in the README is generated from test output by a script**
   (`tools/generate_readme.py`). No hand-typed metrics. CI fails if the
   README is stale.
3. **Every rule needs** ATT&CK technique tags, at least one attack fixture,
   at least one benign fixture, and a write-up in `docs/`.
4. **Every write-up has a "Known blind spots" section** that honestly says
   how the rule can be evaded or where it fails.
5. **No working malware, exploit code, or offensive tooling in the repo.**
   Reference Atomic Red Team test numbers and GUIDs instead of copying attack
   scripts. Raw `.evtx` files are gitignored; only the converted, reviewed
   JSON fixtures are committed.
6. **No employer or client information anywhere.** This is a personal lab.
7. **No em dashes and no emoji in prose.** Write like a person, not a
   textbook. A test scans Markdown and rule files for both.

When a request conflicts with these rules, say so instead of quietly working
around it. When a rule fails on real data, fix the rule or record the miss
honestly (see `known_gap` below). Never loosen a rule just to make a test
pass, and never edit a real fixture's events.

## Repo structure

```
rules/                one Sigma YAML per detection, named by technique (t1003_001_*.yml)
fixtures/attack/      real exported attack runs, one folder per technique (t1003.001/)
fixtures/benign/      real benign exports: common/ is replayed against every rule,
                      <technique>/ holds per-technique extras
fixtures/synthetic/   hand-written placeholder data, same attack/benign layout,
                      never counted in metrics
tests/                replay harness (harness.py) and pytest tests
tools/                evtx_to_fixture.py, generate_readme.py
docs/                 one write-up per rule, plus LAB_SETUP.md and METHODOLOGY.md
.github/workflows/    CI: rule validation, tests, README freshness check
```

## How replay works

`tests/harness.py` uses pySigma to parse each rule. It applies the Sysmon
and Windows logsource pipelines, which add the `Channel` and `EventID`
conditions a real SIEM would add, and converts the rule to SQL with the
pySigma SQLite backend. Each fixture's events are loaded into an in-memory
SQLite table (columns `NUMERIC COLLATE NOCASE`, so matching is
case-insensitive the way Sigma specifies) and the query is run against it.

- An **attack run** counts as detected if at least one of its events matches.
- A **benign event** counts as a false positive if it matches.

## Fixture format

One JSON file per run (attack) or per export (benign):

```json
{
  "metadata": {
    "synthetic": false,
    "kind": "attack",
    "technique": "T1003.001",
    "date": "2026-10-20",
    "source": "win11-lab VM, Sysmon 15.15, SwiftOnSecurity config + lsass include",
    "atomic_test": {"technique": "T1003.001", "number": 1, "guid": "0be2230c-..."},
    "variant": "baseline",
    "description": "what was run and why it belongs here",
    "known_gap": "optional: why the rule is expected to miss (or flag) this"
  },
  "events": [ { "Channel": "...", "EventID": 10, "...": "flat Sysmon/Security fields" } ]
}
```

`known_gap` turns the test into a strict xfail: it still counts against the
metrics, and the test fails if the rule starts behaving differently, so the
gap gets revisited.

## Commands

```
uv venv --python 3.12 .venv && uv pip install -r requirements.txt   # or python3.11+ -m venv
.venv/bin/pytest                          # writes build/results.json
.venv/bin/python tools/generate_readme.py  # rewrites the README coverage block
```

## Dependencies

Python 3.11+, pinned in `requirements.txt`: pySigma 1.5.1,
pySigma-backend-sqlite, pySigma-pipeline-sysmon, pySigma-pipeline-windows,
python-evtx, pytest, PyYAML. Ask before installing anything globally.

## Working style

The author is new to detection engineering. Explain design decisions and
jargon briefly in plain language. Work one technique at a time, in phases,
and stop at each checkpoint for review.
