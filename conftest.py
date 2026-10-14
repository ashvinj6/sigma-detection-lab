"""Collects one result record per replay test and writes build/results.json.

tools/generate_readme.py reads that file, so README numbers always come from
an actual test run.
"""
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

from harness import ROOT  # noqa: E402

RESULTS_PATH = ROOT / "build" / "results.json"
_records = []


@pytest.fixture
def record():
    def _record(**fields):
        _records.append(fields)

    return _record


def pytest_sessionfinish(session, exitstatus):
    RESULTS_PATH.parent.mkdir(exist_ok=True)
    payload = {
        "exit_status": int(exitstatus),
        "tests_collected": session.testscollected,
        "tests_failed": session.testsfailed,
        "records": sorted(_records, key=lambda r: (r["rule"], r["fixture"])),
    }
    RESULTS_PATH.write_text(json.dumps(payload, indent=2) + "\n")
