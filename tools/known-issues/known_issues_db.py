#!/usr/bin/env python3
"""
Known-issues database for PAN Copilot.

A retroactive, searchable corpus of Palo Alto Networks "Addressed Issues" pulled
from release notes. PAN Copilot queries this at runtime: given a user's running
version and a symptom, it returns issues that are FIXED in a later release of the
same train, meaning the bug is likely present in what the user is running.

This is deliberately NOT in the system prompt. The corpus is thousands of rows
across every PAN-OS train, far larger than a prompt can hold. The prompt holds
only the procedure for using this database (see the updater's LOOKUP_PROCEDURE).

Storage: SQLite with an FTS5 index on the description for symptom search.
Dependency free (sqlite3 ships with Python).

ADKCyber. Author: Jack Miller.
"""

import argparse
import json
import os
import re
import sqlite3
from datetime import datetime, timezone

DB_PATH = os.getenv("KNOWN_ISSUES_DB", "known_issues.db")

# major.feature.maintenance with optional -hN hotfix, optional "PAN-OS " prefix.
_VER_RE = re.compile(r"(?:PAN-?OS\s*)?(\d+)\.(\d+)\.(\d+)(?:-h(\d+))?", re.IGNORECASE)


def parse_panos_version(version: str):
    """Return (major, feature, maint, hotfix) or None if unparseable."""
    if not version:
        return None
    m = _VER_RE.search(version)
    if not m:
        return None
    major, feature, maint = int(m.group(1)), int(m.group(2)), int(m.group(3))
    hotfix = int(m.group(4)) if m.group(4) else 0
    return (major, feature, maint, hotfix)


def train_of(version: str):
    """Return the train string, for example '11.1', or None."""
    parsed = parse_panos_version(version)
    if not parsed:
        return None
    return f"{parsed[0]}.{parsed[1]}"


def now_iso():
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


class KnownIssuesDB:
    def __init__(self, path: str = DB_PATH):
        self.path = path
        self.conn = sqlite3.connect(path)
        self.conn.row_factory = sqlite3.Row
        self._init_schema()

    def _init_schema(self):
        cur = self.conn.cursor()
        cur.executescript(
            """
            CREATE TABLE IF NOT EXISTS issues (
                issue_id      TEXT,
                train         TEXT,
                fixed_in      TEXT,
                fixed_major   INTEGER,
                fixed_feature INTEGER,
                fixed_maint   INTEGER,
                fixed_hotfix  INTEGER,
                component     TEXT,
                description   TEXT,
                source_url    TEXT,
                ingested_at   TEXT,
                UNIQUE(issue_id, fixed_in)
            );
            CREATE INDEX IF NOT EXISTS idx_train ON issues(train);

            CREATE VIRTUAL TABLE IF NOT EXISTS issues_fts
                USING fts5(description, content='issues', content_rowid='rowid');

            CREATE TRIGGER IF NOT EXISTS issues_ai AFTER INSERT ON issues BEGIN
                INSERT INTO issues_fts(rowid, description) VALUES (new.rowid, new.description);
            END;
            CREATE TRIGGER IF NOT EXISTS issues_ad AFTER DELETE ON issues BEGIN
                INSERT INTO issues_fts(issues_fts, rowid, description)
                VALUES('delete', old.rowid, old.description);
            END;
            """
        )
        self.conn.commit()

    def add_issue(self, issue_id, fixed_in, description, component="", source_url=""):
        parsed = parse_panos_version(fixed_in)
        if not parsed:
            return False
        major, feature, maint, hotfix = parsed
        train = f"{major}.{feature}"
        try:
            self.conn.execute(
                """INSERT OR IGNORE INTO issues
                   (issue_id, train, fixed_in, fixed_major, fixed_feature, fixed_maint,
                    fixed_hotfix, component, description, source_url, ingested_at)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                (str(issue_id).strip(), train, fixed_in, major, feature, maint, hotfix,
                 component.strip(), description.strip(), source_url, now_iso()),
            )
            return True
        except sqlite3.Error:
            return False

    def bulk_add(self, rows) -> int:
        added = 0
        for r in rows:
            if self.add_issue(
                r.get("issue_id", ""),
                r.get("fixed_in", ""),
                r.get("description", ""),
                r.get("component", ""),
                r.get("source_url", ""),
            ):
                added += 1
        self.conn.commit()
        return added

    def search(self, running_version: str, query: str = "", limit: int = 15):
        """
        Return issues fixed in a later release of the same train than running_version.

        Heuristic: a defect fixed in version F of train T is assumed present in all
        earlier maintenance/hotfix releases of T. Cross-train inference is not made,
        because PAN tracks fixes per train.
        """
        parsed = parse_panos_version(running_version)
        if not parsed:
            return {"error": f"Could not parse version '{running_version}'", "matches": []}
        major, feature, maint, hotfix = parsed
        train = f"{major}.{feature}"

        params = [train, maint, maint, hotfix]
        sql = """
            SELECT issue_id, fixed_in, component, description, source_url
            FROM issues
            WHERE train = ?
              AND (fixed_maint > ? OR (fixed_maint = ? AND fixed_hotfix > ?))
        """
        if query.strip():
            fts = _fts_query(query)
            sql += " AND rowid IN (SELECT rowid FROM issues_fts WHERE issues_fts MATCH ?)"
            params.append(fts)
        sql += " ORDER BY fixed_maint, fixed_hotfix LIMIT ?"
        params.append(limit)

        rows = [dict(r) for r in self.conn.execute(sql, params).fetchall()]
        return {
            "running_version": running_version,
            "train": train,
            "match_count": len(rows),
            "matches": rows,
        }

    def stats(self):
        cur = self.conn.execute("SELECT COUNT(*) n, COUNT(DISTINCT train) t FROM issues")
        row = cur.fetchone()
        trains = [r["train"] for r in self.conn.execute(
            "SELECT DISTINCT train FROM issues ORDER BY train").fetchall()]
        return {"issues": row["n"], "trains": row["t"], "train_list": trains}

    def close(self):
        self.conn.commit()
        self.conn.close()


def _fts_query(query: str) -> str:
    # Turn a free-text symptom into a safe OR query of word tokens.
    tokens = re.findall(r"[A-Za-z0-9]+", query)
    tokens = [t for t in tokens if len(t) > 2]
    return " OR ".join(tokens) if tokens else query


def _cli():
    p = argparse.ArgumentParser(description="Query or inspect the PAN known-issues DB.")
    p.add_argument("--db", default=DB_PATH)
    p.add_argument("--version", help="Running PAN-OS version, for example 11.1.2")
    p.add_argument("--query", default="", help="Symptom keywords")
    p.add_argument("--limit", type=int, default=15)
    p.add_argument("--stats", action="store_true")
    p.add_argument("--json", action="store_true", help="Raw JSON output")
    args = p.parse_args()

    db = KnownIssuesDB(args.db)
    if args.stats or not args.version:
        out = db.stats()
        print(json.dumps(out, indent=2))
        db.close()
        return

    result = db.search(args.version, args.query, args.limit)
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        if result.get("error"):
            print(result["error"])
        elif result["match_count"] == 0:
            print(f"No known fixed issues match version {args.version} "
                  f"(train {result['train']}) for that symptom.")
        else:
            print(f"{result['match_count']} known issue(s) fixed after {args.version} "
                  f"(train {result['train']}):\n")
            for r in result["matches"]:
                print(f"  [{r['issue_id']}] fixed in {r['fixed_in']}"
                      f"{' / ' + r['component'] if r['component'] else ''}")
                print(f"      {r['description']}")
                if r["source_url"]:
                    print(f"      source: {r['source_url']}")
    db.close()


if __name__ == "__main__":
    _cli()
