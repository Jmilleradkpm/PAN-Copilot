"""
Tests for the runtime known-issues lookup (local/known_issues.py).

This module is the cloud-path companion to the build-time pipeline in
tools/known-issues/. Given a chat message that mentions a running PAN-OS
version PLUS a symptom, it returns a compact reference block of defects fixed
in a LATER maintenance/hotfix release of the same train (i.e. bugs likely
present in what the user is running) to append to the system prompt.

The module is stdlib-only and decoupled from app.py, so these tests run
without the FastAPI/Anthropic desktop stack.

Run from the `local/` directory:  pytest tests/test_known_issues.py
"""

import sqlite3

import pytest

from known_issues import detect_version, known_issues_context


# ---------------------------------------------------------------------------
# Temp DB helper — mirrors tools/known-issues/known_issues_db.py schema so the
# FTS symptom-search path is exercised exactly as in production.
# ---------------------------------------------------------------------------

def _make_db(path, rows):
    conn = sqlite3.connect(str(path))
    conn.executescript(
        """
        CREATE TABLE issues (
            issue_id TEXT, train TEXT, fixed_in TEXT,
            fixed_major INTEGER, fixed_feature INTEGER,
            fixed_maint INTEGER, fixed_hotfix INTEGER,
            component TEXT, description TEXT, source_url TEXT, ingested_at TEXT,
            UNIQUE(issue_id, fixed_in)
        );
        CREATE VIRTUAL TABLE issues_fts
            USING fts5(description, content='issues', content_rowid='rowid');
        CREATE TRIGGER issues_ai AFTER INSERT ON issues BEGIN
            INSERT INTO issues_fts(rowid, description) VALUES (new.rowid, new.description);
        END;
        """
    )
    for r in rows:
        major, feature, maint, hotfix = r["v"]
        conn.execute(
            """INSERT INTO issues (issue_id, train, fixed_in, fixed_major,
               fixed_feature, fixed_maint, fixed_hotfix, component, description,
               source_url, ingested_at)
               VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
            (r["id"], f"{major}.{feature}", r["fixed_in"], major, feature, maint,
             hotfix, r.get("component", ""), r["desc"], r.get("url", ""), "t"),
        )
    conn.commit()
    conn.close()


# A small corpus: four issues in train 11.1, one in 10.2 (cross-train guard).
_ROWS = [
    {"id": "WB-A", "v": (11, 1, 6, 0),  "fixed_in": "11.1.6",
     "desc": "GlobalProtect tunnel drops after phase2 rekey", "url": "http://x/A"},
    {"id": "WB-B", "v": (11, 1, 8, 0),  "fixed_in": "11.1.8",
     "desc": "dataplane reboot following commit on an HA pair"},
    {"id": "WB-C", "v": (11, 1, 6, 0),  "fixed_in": "11.1.6",
     "desc": "stored XSS in the management web console dashboard"},
    {"id": "WB-D", "v": (11, 1, 10, 0), "fixed_in": "11.1.10",
     "desc": "BGP route flap during a failover event"},
    {"id": "WB-E", "v": (10, 2, 9, 0),  "fixed_in": "10.2.9",
     "desc": "tunnel drops on the tunnel interface under load"},
]


@pytest.fixture()
def db(tmp_path):
    p = tmp_path / "known_issues.db"
    _make_db(p, _ROWS)
    return p


# ---------------------------------------------------------------------------
# detect_version — parsing + adversarial negatives
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("text,expected", [
    ("we are running PAN-OS 11.1.4 and seeing issues", (11, 1, 4, 0)),
    ("on 10.2.8", (10, 2, 8, 0)),
    ("11.1.6-h3 deployment broke things", (11, 1, 6, 3)),
    ("PANOS 12.1.2", (12, 1, 2, 0)),
    ("v11.2.0 hangs on boot", (11, 2, 0, 0)),
    ("we run 10.2.18. then it crashed", (10, 2, 18, 0)),   # sentence-final period
])
def test_detect_version_positives(text, expected):
    parsed = detect_version(text)
    assert parsed is not None, f"expected to parse a version from {text!r}"
    assert parsed[:4] == expected


@pytest.mark.parametrize("text", [
    "firewall management IP is 10.2.18.5",   # IPv4 — must NOT parse as a version
    "192.168.1.1 is the gateway",            # IPv4
    "we're on 11.1 train",                   # train only, no maintenance level
    "no version mentioned at all here",
    "",
    "the config paste is 8000 chars long",
])
def test_detect_version_negatives(text):
    assert detect_version(text) is None


# ---------------------------------------------------------------------------
# known_issues_context — retrieval, gating, isolation, fail-safe
# ---------------------------------------------------------------------------

def test_returns_matching_later_issues_for_version_plus_symptom(db):
    block = known_issues_context("We're running 11.1.4 and seeing tunnel drops", db)
    assert "WB-A" in block                 # 11.1.6, matches "tunnel"/"drops"
    assert "11.1.6" in block
    assert "WB-B" not in block             # symptom filter: no tunnel/drops
    assert "WB-D" not in block             # symptom filter: BGP, not tunnel
    assert "WB-E" not in block             # cross-train: 10.2 must never appear
    assert "11.1" in block                 # train shown in the header


def test_no_issues_when_running_newer_than_all_fixes(db):
    # 11.1.10 is >= every fixed_in in train 11.1, so nothing is "later".
    assert known_issues_context("on 11.1.10 with tunnel drops", db) == ""


def test_bare_version_without_symptom_returns_empty(db):
    # Symptom-gated: a version with no real symptom keywords must not dump issues.
    assert known_issues_context("I'm on 11.1.4", db) == ""


def test_unknown_train_returns_empty(db):
    # Parses as a version but no such train exists in the corpus.
    assert known_issues_context("device 3.2.1 has tunnel drops", db) == ""


def test_no_version_returns_empty(db):
    assert known_issues_context("my tunnel keeps dropping, help", db) == ""


def test_missing_db_is_failsafe(tmp_path):
    missing = tmp_path / "does_not_exist.db"
    assert known_issues_context("11.1.4 tunnel drops", missing) == ""


def test_long_descriptions_are_truncated(tmp_path):
    long_desc = "tunnel " + ("x" * 600)
    _make_db(tmp_path / "k.db", [
        {"id": "WB-LONG", "v": (11, 1, 6, 0), "fixed_in": "11.1.6", "desc": long_desc},
    ])
    block = known_issues_context("11.1.4 tunnel issue", tmp_path / "k.db")
    assert "WB-LONG" in block
    assert "…" in block                    # truncation marker present
    assert "x" * 600 not in block          # raw long description not dumped verbatim
