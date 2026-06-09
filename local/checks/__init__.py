"""Config hygiene / best-practice checks for PAN-OS security policy.

Parses security rules from a PAN-OS config (XML candidate/running export or a
set-format paste) and flags common best-practice gaps: any-any rules, allow
rules with no security profiles, missing logging, service/app over-permissions,
disabled rules, and simple rule shadowing. Read-only analysis — never mutates.
"""
from .engine import CheckFinding, CheckResult, run_checks

__all__ = ["CheckFinding", "CheckResult", "run_checks"]
