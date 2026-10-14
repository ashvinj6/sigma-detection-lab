"""Enforces the repo rules in CLAUDE.md that a machine can check."""
import json
import re

import pytest
from sigma.collection import SigmaCollection
from sigma.validation import SigmaValidator
from sigma.validators.core import validators

from harness import FIXTURES_DIR, ROOT, all_fixture_paths, fixtures_for, load_fixture, load_rules

RULES = load_rules()
FIXTURE_PATHS = all_fixture_paths()
DOCS_DIR = ROOT / "docs"


def _rule_id(rule):
    return rule.path.stem


def _fixture_id(path):
    return path.relative_to(ROOT).as_posix()


# ---- rules -----------------------------------------------------------------

def test_there_is_at_least_one_rule():
    assert RULES


@pytest.mark.parametrize("rule", RULES, ids=_rule_id)
def test_rule_passes_pysigma_validators(rule):
    issues = SigmaValidator(validators.values()).validate_rules(SigmaCollection([rule.sigma]))
    assert not issues, "\n".join(str(i) for i in issues)


@pytest.mark.parametrize("rule", RULES, ids=_rule_id)
def test_rule_has_technique_tag_and_matching_filename(rule):
    assert rule.technique_ids, f"{rule.path.name} has no attack.tNNNN(.NNN) tag"
    slug = rule.technique_ids[0].lower().replace(".", "_")
    assert rule.path.name.startswith(slug + "_"), f"{rule.path.name} should start with {slug}_"


@pytest.mark.parametrize("rule", RULES, ids=_rule_id)
def test_rule_converts_to_sql(rule):
    assert rule.sql


@pytest.mark.parametrize("rule", RULES, ids=_rule_id)
def test_rule_has_attack_and_benign_fixtures(rule):
    """Rule 3. A rule may run on synthetic data alone only while its status is experimental."""
    needs_real = rule.sigma.status is not None and rule.sigma.status.name.lower() in ("test", "stable")
    for technique_id in rule.technique_ids:
        for kind in ("attack", "benign"):
            real = fixtures_for(technique_id, kind, synthetic=False)
            synthetic = fixtures_for(technique_id, kind, synthetic=True)
            if needs_real:
                assert real, f"{rule.path.name} is '{rule.sigma.status.name.lower()}' but has no real {kind} fixtures"
            else:
                assert real or synthetic, f"{rule.path.name} has no {kind} fixtures for {technique_id}"


@pytest.mark.parametrize("rule", RULES, ids=_rule_id)
def test_rule_has_writeup_with_blind_spots(rule):
    """Rules 3 and 4."""
    doc = DOCS_DIR / f"{rule.path.stem}.md"
    assert doc.is_file(), f"missing write-up {doc.relative_to(ROOT)}"
    sections = re.split(r"^## ", doc.read_text(), flags=re.MULTILINE)
    blind = [s for s in sections if s.lower().startswith("known blind spots")]
    assert blind, f"{doc.name} has no '## Known blind spots' section"
    body = blind[0].split("\n", 1)[1] if "\n" in blind[0] else ""
    assert len(body.strip()) > 100, f"{doc.name}: 'Known blind spots' section is nearly empty"


# ---- fixtures --------------------------------------------------------------

@pytest.mark.parametrize("path", FIXTURE_PATHS, ids=_fixture_id)
def test_fixture_metadata_is_honest(path):
    """Rule 1: synthetic data lives under fixtures/synthetic/ and says so, and nothing else does."""
    json.loads(path.read_text())
    fx = load_fixture(path)
    parts = path.relative_to(FIXTURES_DIR).parts
    in_synthetic = parts[0] == "synthetic"
    if in_synthetic:
        parts = parts[1:]
    md = fx.metadata

    assert isinstance(md.get("synthetic"), bool), "metadata.synthetic must be true or false"
    assert md["synthetic"] is in_synthetic, (
        "synthetic fixtures must live under fixtures/synthetic/ and real ones must not"
    )
    assert len(parts) == 3 and parts[0] in ("attack", "benign"), "expected <attack|benign>/<technique|common>/<name>.json"
    assert md.get("kind") == parts[0], f"metadata.kind should be '{parts[0]}'"
    if parts[1] != "common":
        assert str(md.get("technique", "")).lower() == parts[1], f"metadata.technique should be {parts[1].upper()}"
    for key in ("date", "source", "description"):
        assert md.get(key), f"metadata.{key} is required"
    if md["kind"] == "attack" and not md["synthetic"]:
        assert md.get("atomic_test", {}).get("guid"), "real attack runs must reference the Atomic test GUID"
    assert isinstance(fx.events, list) and fx.events, "events must be a non-empty list"
    assert all(isinstance(e, dict) for e in fx.events), "each event must be a JSON object"


# ---- prose -----------------------------------------------------------------

_BANNED = re.compile(
    "[–—―]"  # en dash, em dash, horizontal bar
    "|[\U0001F300-\U0001FAFF\U00002600-\U000027BF\U0001F000-\U0001F2FF️]"  # emoji
)
PROSE_FILES = sorted(
    [p for p in ROOT.glob("*.md")]
    + list(DOCS_DIR.glob("*.md"))
    + list((ROOT / "fixtures").glob("*.md"))
    + list((ROOT / "rules").glob("*.yml"))
)


@pytest.mark.parametrize("path", PROSE_FILES, ids=_fixture_id)
def test_no_em_dashes_or_emoji(path):
    """Rule 7."""
    bad = [f"line {n}: {line.strip()[:80]}" for n, line in enumerate(path.read_text().splitlines(), 1)
           if _BANNED.search(line)]
    assert not bad, "\n".join(bad)
