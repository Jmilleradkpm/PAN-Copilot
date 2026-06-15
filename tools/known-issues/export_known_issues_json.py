#!/usr/bin/env python3
"""
Export the known-issues SQLite DB to a flat JSON file.

The .NET app (ADK Cyber AI v3) cannot read SQLite without a native library
(e_sqlite3.dll), which would reintroduce the antivirus-false-positive trigger
the .NET rewrite exists to eliminate. So the corpus ships to that consumer as
JSON it can read with the managed System.Text.Json. The Python desktop app
reads the .db directly.

Usage (run after an ingest, from tools/known-issues/):
    python export_known_issues_json.py [out.json]

The DB path comes from $KNOWN_ISSUES_DB (default known_issues.db). The output
keys match the .NET KnownIssuesService model exactly.

ADKCyber. Author: Jack Miller.
"""

import json
import os
import sqlite3
import sys
from pathlib import Path

DB_PATH = Path(os.getenv("KNOWN_ISSUES_DB", "known_issues.db"))


def export(db_path: Path, out_path: Path) -> int:
    if not db_path.exists():
        print(f"DB not found: {db_path}", file=sys.stderr)
        return 1
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    try:
        rows = [dict(r) for r in conn.execute(
            "SELECT issue_id, train, fixed_in, fixed_maint, fixed_hotfix, "
            "component, description, source_url FROM issues")]
    finally:
        conn.close()
    out_path.write_text(json.dumps(rows, ensure_ascii=False), encoding="utf-8")
    print(f"Exported {len(rows)} issues -> {out_path} "
          f"({out_path.stat().st_size / 1024:.0f} KB)")
    return 0


def main() -> int:
    out = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("known_issues.json")
    return export(DB_PATH, out)


if __name__ == "__main__":
    sys.exit(main())
