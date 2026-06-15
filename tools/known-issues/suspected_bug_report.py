#!/usr/bin/env python3
"""
Suspected-bug report for PAN Copilot.

This is the second half of the version-lookup flow. When a user's issue does NOT
match a known fixed bug but still looks like a genuine defect, PAN Copilot can
generate a structured report for the user to submit to Palo Alto Networks support.

Important reality check on "automatically notify Palo Alto Networks":

  * If the issue DOES match a known fixed bug, there is nothing to report. The
    fix already exists. The action is "upgrade to the fixed version."
  * Palo Alto Networks has no open, public API to auto-file defects. Bug reports
    go through a TAC support case in the Customer Support Portal (CSP), which
    requires a support entitlement and authenticated account.
  * Auto-sending to a vendor without human review is risky (noise, support-terms,
    and you may leak config detail). So this module DRAFTS and STAGES a report
    for review. Actual submission is disabled by default and, even when enabled,
    requires your CSP credentials and defaults to a dry run.

ADKCyber. Author: Jack Miller.
"""

import argparse
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path

PENDING_REPORTS = Path(os.getenv("PENDING_REPORTS_DIR", "pending/reports"))
ENABLE_SUBMISSION = os.getenv("ENABLE_PAN_CASE_SUBMISSION", "false").lower() == "true"


def now_iso():
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _redact(text: str) -> str:
    """Light redaction so drafts do not carry obvious secrets into a report."""
    text = re.sub(r"(?i)(api[ _-]?key|password|secret|token)\s*[:=]\s*\S+", r"\1: [redacted]", text)
    return text


def generate_report(issue_text, version, checks_done=None, db_result=None) -> dict:
    """Build a structured suspected-bug report."""
    checks_done = checks_done or []
    report = {
        "report_id": f"ADKCYBER-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}",
        "created": now_iso(),
        "panos_version": version,
        "summary": _redact(issue_text.strip())[:200],
        "description": _redact(issue_text.strip()),
        "checks_performed": checks_done,
        "known_issue_match": bool(db_result and db_result.get("match_count")),
        "matched_train": db_result.get("train") if db_result else None,
        "matched_issue_count": db_result.get("match_count", 0) if db_result else 0,
        "recommended_action": (
            "Upgrade to the fixed version (see matched issues)."
            if (db_result and db_result.get("match_count"))
            else "No known fixed issue matched. Candidate for a new TAC case after human review."
        ),
        "submission_status": "draft",
    }
    return report


def to_markdown(report: dict) -> str:
    lines = [
        f"# Suspected PAN-OS Issue Report  ({report['report_id']})",
        f"_Generated {report['created']} by ADKCyber PAN Copilot. Draft for review._",
        "",
        f"**PAN-OS version:** {report['panos_version']}",
        f"**Known-issue match:** {'yes' if report['known_issue_match'] else 'no'}"
        f" ({report['matched_issue_count']} fixed issues in train {report['matched_train']})"
        if report["matched_train"] else f"**Known-issue match:** {'yes' if report['known_issue_match'] else 'no'}",
        "",
        "## Description",
        report["description"],
        "",
        "## Checks performed",
    ]
    lines += [f"- {c}" for c in report["checks_performed"]] or ["- (none recorded)"]
    lines += ["", "## Recommended action", report["recommended_action"], ""]
    return "\n".join(lines)


def stage_report(report: dict) -> Path:
    PENDING_REPORTS.mkdir(parents=True, exist_ok=True)
    base = PENDING_REPORTS / report["report_id"]
    base.with_suffix(".json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    md = base.with_suffix(".md")
    md.write_text(to_markdown(report), encoding="utf-8")
    return md


class PanCaseNotifier:
    """
    Gated submission hook for the Palo Alto Networks Customer Support Portal.

    Disabled by default. There is no fabricated endpoint here. To wire real
    submission you must supply your CSP / TAC case credentials and implement the
    call against the support API you are entitled to use, then set
    ENABLE_PAN_CASE_SUBMISSION=true. It still defaults to dry_run.
    """

    def __init__(self):
        self.enabled = ENABLE_SUBMISSION

    def submit(self, report: dict, dry_run: bool = True) -> dict:
        if not self.enabled:
            return {
                "status": "disabled",
                "message": (
                    "PAN case submission is disabled. The report has been drafted for "
                    "manual submission via the Palo Alto Networks Customer Support Portal."
                ),
            }
        if dry_run:
            return {"status": "dry_run", "message": "Would submit report to PAN CSP (dry run).",
                    "report_id": report["report_id"]}
        # ⚠️ Live submission path. Implement against your entitled CSP/TAC case API.
        raise NotImplementedError(
            "Live PAN case submission is not implemented. Wire your CSP/TAC case API and "
            "credentials here, with explicit per-case approval, before enabling."
        )


def _cli():
    p = argparse.ArgumentParser(description="Generate a suspected-bug report draft.")
    p.add_argument("--version", required=True)
    p.add_argument("--issue", required=True, help="Description of the problem.")
    p.add_argument("--check", action="append", default=[], help="A check already performed (repeatable).")
    args = p.parse_args()
    report = generate_report(args.issue, args.version, args.check)
    path = stage_report(report)
    print(f"Draft staged: {path}")
    print(PanCaseNotifier().submit(report))


if __name__ == "__main__":
    _cli()
