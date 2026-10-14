"""Replay harness: converts Sigma rules to SQL and runs them over fixture events.

Each rule is converted with the pySigma SQLite backend after the Sysmon and
Windows logsource pipelines run, so the query carries the same Channel and
EventID constraints a SIEM would add. Each fixture's events go into a fresh
in-memory SQLite table and the query runs against it.

Two details keep SQLite's behavior close to the Sigma spec:
  * every column is ``NUMERIC COLLATE NOCASE``. NOCASE makes ``=`` comparisons
    case-insensitive (``LIKE`` already is). NUMERIC lets ``EventID: 10`` in a
    rule match an event that stored "10" as a string. Hex strings such as
    "0x1410" are not valid numbers to SQLite, so they stay text.
  * a Python ``REGEXP`` function is registered for the ``|re`` modifier.
"""
import json
import re
import sqlite3
from dataclasses import dataclass, field
from functools import cached_property
from pathlib import Path
from typing import List, Optional

from sigma.backends.sqlite import sqliteBackend
from sigma.collection import SigmaCollection
from sigma.pipelines.sysmon import sysmon_pipeline
from sigma.pipelines.windows import windows_logsource_pipeline
from sigma.rule import SigmaDetection, SigmaDetectionItem, SigmaRule

ROOT = Path(__file__).resolve().parent.parent
RULES_DIR = ROOT / "rules"
FIXTURES_DIR = ROOT / "fixtures"

_TECHNIQUE_TAG_RE = re.compile(r"^t(\d{4}(?:\.\d{3})?)$", re.IGNORECASE)
_SELECT_PREFIX = "SELECT * FROM logs WHERE "


def _backend() -> sqliteBackend:
    return sqliteBackend(processing_pipeline=sysmon_pipeline() + windows_logsource_pipeline())


def _regexp(pattern, value) -> bool:
    return value is not None and re.search(pattern, str(value)) is not None


def _detection_fields(detection: SigmaDetection) -> set:
    fields = set()
    for item in detection.detection_items:
        if isinstance(item, SigmaDetection):
            fields |= _detection_fields(item)
        elif isinstance(item, SigmaDetectionItem) and item.field:
            fields.add(item.field)
    return fields


@dataclass
class Rule:
    path: Path
    sigma: SigmaRule

    @property
    def title(self) -> str:
        return self.sigma.title

    @property
    def technique_ids(self) -> List[str]:
        ids = []
        for tag in self.sigma.tags:
            m = _TECHNIQUE_TAG_RE.match(tag.name)
            if tag.namespace.lower() == "attack" and m:
                ids.append("T" + m.group(1).upper())
        return ids

    @cached_property
    def sql(self) -> str:
        queries = _backend().convert(SigmaCollection([self.sigma]))
        if len(queries) != 1 or not queries[0].startswith(_SELECT_PREFIX):
            raise ValueError(f"{self.path.name}: unexpected SQL from backend: {queries!r}")
        return queries[0]

    @cached_property
    def fields(self) -> set:
        """Field names the query may reference, including pipeline-added ones."""
        names = {"Channel", "EventID"}
        for detection in self.sigma.detection.detections.values():
            names |= _detection_fields(detection)
        return names

    def matching_indexes(self, events: List[dict]) -> List[int]:
        """Return the positions of the events this rule fires on."""
        # SQLite column names are case-insensitive, and Sysmon itself is not
        # consistent (EID 10 says SourceProcessGUID, EID 8 says SourceProcessGuid),
        # so columns are keyed by lowercased name.
        columns = {}
        for name in sorted(self.fields) + [k for e in events for k in e]:
            columns.setdefault(name.lower(), name)
        db = sqlite3.connect(":memory:")
        db.create_function("REGEXP", 2, _regexp, deterministic=True)
        col_defs = ", ".join(f'"{c}" NUMERIC COLLATE NOCASE' for c in columns.values())
        db.execute(f'CREATE TABLE logs ("_row" INTEGER, {col_defs})')
        placeholders = ", ".join("?" for _ in range(len(columns) + 1))
        rows = []
        for i, event in enumerate(events):
            lowered = {k.lower(): v for k, v in event.items()}
            rows.append([i] + [_scalar(lowered.get(c)) for c in columns])
        db.executemany(f"INSERT INTO logs VALUES ({placeholders})", rows)
        query = 'SELECT "_row" FROM logs WHERE ' + self.sql[len(_SELECT_PREFIX):]
        rows = sorted(r[0] for r in db.execute(query))
        db.close()
        return rows


def _scalar(value):
    if isinstance(value, (dict, list)):
        return json.dumps(value)
    return value


def load_rule(path: Path) -> Rule:
    rules = list(SigmaCollection.from_yaml(Path(path).read_text()).rules)
    if len(rules) != 1:
        raise ValueError(f"{path} must contain exactly one Sigma rule, found {len(rules)}")
    return Rule(path=Path(path), sigma=rules[0])


def load_rules(rules_dir: Path = RULES_DIR) -> List[Rule]:
    return [load_rule(p) for p in sorted(Path(rules_dir).glob("*.yml"))]


@dataclass
class Fixture:
    path: Path
    metadata: dict
    events: List[dict] = field(repr=False)

    @property
    def synthetic(self) -> bool:
        return self.metadata.get("synthetic") is True

    @property
    def kind(self) -> str:
        return self.metadata.get("kind", "")

    @property
    def known_gap(self) -> Optional[str]:
        return self.metadata.get("known_gap")

    @property
    def rel(self) -> str:
        return self.path.relative_to(ROOT).as_posix()


def load_fixture(path: Path) -> Fixture:
    data = json.loads(Path(path).read_text())
    return Fixture(path=Path(path), metadata=data.get("metadata", {}), events=data.get("events", []))


def all_fixture_paths(root: Path = FIXTURES_DIR) -> List[Path]:
    return sorted(Path(root).rglob("*.json"))


def fixtures_for(technique_id: str, kind: str, synthetic: bool, root: Path = FIXTURES_DIR) -> List[Fixture]:
    """Attack fixtures for a technique, or benign fixtures (common + technique)."""
    base = Path(root) / "synthetic" if synthetic else Path(root)
    dirs = [base / kind / technique_id.lower()]
    if kind == "benign":
        dirs.insert(0, base / "benign" / "common")
    paths = [p for d in dirs if d.is_dir() for p in sorted(d.glob("*.json"))]
    return [load_fixture(p) for p in paths]
