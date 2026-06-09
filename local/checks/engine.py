"""PAN-OS security-policy hygiene checks.

Input is a PAN-OS config as text — either an XML export (running/candidate, e.g.
from `show config running` or the API) or a set-format paste. We extract the
security rulebase and run best-practice checks against it.

The output mirrors the migration report shape (severity/category/message +
remediation) so the frontend and chat can render it consistently.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional
from xml.etree import ElementTree as ET


class Severity(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class SecurityRule:
    name: str
    action: str = "allow"
    from_zones: list[str] = field(default_factory=list)
    to_zones: list[str] = field(default_factory=list)
    source: list[str] = field(default_factory=list)
    destination: list[str] = field(default_factory=list)
    application: list[str] = field(default_factory=list)
    service: list[str] = field(default_factory=list)
    disabled: bool = False
    log_end: bool = True          # PAN-OS defaults log-end to yes on new rules
    log_setting: Optional[str] = None
    has_profiles: bool = False    # profile-setting/profiles or group present


@dataclass
class CheckFinding:
    severity: Severity
    category: str
    rule: str
    message: str
    remediation: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "severity": self.severity.value,
            "category": self.category,
            "rule": self.rule,
            "message": self.message,
            "remediation": self.remediation,
        }


@dataclass
class CheckResult:
    source_format: str
    rule_count: int
    findings: list[CheckFinding] = field(default_factory=list)

    def add(self, severity, category, rule, message, remediation):
        self.findings.append(CheckFinding(severity, category, rule, message, remediation))

    def summary(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for f in self.findings:
            counts[f.severity.value] = counts.get(f.severity.value, 0) + 1
        return counts

    def to_dict(self) -> dict[str, Any]:
        return {
            "source_format": self.source_format,
            "rule_count": self.rule_count,
            "summary": self.summary(),
            "findings": [f.to_dict() for f in self.findings],
        }


_ANY = {"any"}


def _members(entry: ET.Element, tag: str) -> list[str]:
    node = entry.find(tag)
    if node is None:
        return []
    members = [m.text.strip() for m in node.findall("member") if m.text]
    if not members and node.text and node.text.strip():
        members = [node.text.strip()]
    return members


def _parse_xml(text: str) -> Optional[list[SecurityRule]]:
    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        return None
    # Find any security rulebase anywhere in the tree (vsys, device-group, shared).
    rules: list[SecurityRule] = []
    for rulebase in root.iter("security"):
        rules_node = rulebase.find("rules")
        if rules_node is None:
            continue
        for entry in rules_node.findall("entry"):
            name = entry.get("name", "(unnamed)")
            r = SecurityRule(name=name)
            r.action = (entry.findtext("action") or "allow").strip()
            r.from_zones = _members(entry, "from")
            r.to_zones = _members(entry, "to")
            r.source = _members(entry, "source")
            r.destination = _members(entry, "destination")
            r.application = _members(entry, "application")
            r.service = _members(entry, "service")
            r.disabled = (entry.findtext("disabled") or "no").strip().lower() == "yes"
            le = entry.findtext("log-end")
            r.log_end = (le or "yes").strip().lower() == "yes"
            r.log_setting = entry.findtext("log-setting")
            r.has_profiles = (
                entry.find("profile-setting/profiles") is not None
                or entry.find("profile-setting/group") is not None
            )
            rules.append(r)
    return rules or None


_SET_RE = re.compile(
    r"^set\s+.*?\brulebase\s+security\s+rules\s+"
    r'("[^"]+"|\S+)\s+(.*)$', re.IGNORECASE)


def _parse_set(text: str) -> Optional[list[SecurityRule]]:
    rules: dict[str, SecurityRule] = {}
    found = False
    for line in text.splitlines():
        m = _SET_RE.match(line.strip())
        if not m:
            continue
        found = True
        name = m.group(1).strip('"')
        rest = m.group(2).strip()
        r = rules.setdefault(name, SecurityRule(name=name))
        # rest looks like: <field> [ <members...> ] | <field> <value>
        fm = re.match(r"(\S+)\s+(.*)$", rest)
        if not fm:
            continue
        field_name, value = fm.group(1).lower(), fm.group(2).strip()
        members = re.findall(r'"[^"]+"|\S+', value.strip("[] "))
        members = [x.strip('"') for x in members]
        if field_name == "action":
            r.action = members[0] if members else "allow"
        elif field_name == "from":
            r.from_zones = members
        elif field_name == "to":
            r.to_zones = members
        elif field_name == "source":
            r.source = members
        elif field_name == "destination":
            r.destination = members
        elif field_name == "application":
            r.application = members
        elif field_name == "service":
            r.service = members
        elif field_name == "disabled":
            r.disabled = members and members[0].lower() == "yes"
        elif field_name == "log-end":
            r.log_end = not (members and members[0].lower() == "no")
        elif field_name == "log-setting":
            r.log_setting = members[0] if members else None
        elif field_name == "profile-setting":
            r.has_profiles = True
    return list(rules.values()) if found else None


def parse_rules(text: str) -> tuple[str, list[SecurityRule]]:
    """Return (source_format, rules). Tries XML first, then set-format."""
    xml_rules = _parse_xml(text)
    if xml_rules is not None:
        return "xml", xml_rules
    set_rules = _parse_set(text)
    if set_rules is not None:
        return "set", set_rules
    return "unknown", []


def _covers(broad: list[str], narrow: list[str]) -> bool:
    """True if `broad` is 'any' or a superset of `narrow` (member-wise)."""
    if set(broad) & _ANY:
        return True
    if not narrow:
        return False
    return set(narrow).issubset(set(broad))


def run_checks(text: str) -> CheckResult:
    fmt, rules = parse_rules(text)
    result = CheckResult(source_format=fmt, rule_count=len(rules))
    if not rules:
        return result

    enabled_allow = []
    for r in rules:
        if r.disabled:
            result.add(Severity.INFO, "disabled-rule", r.name,
                       "Rule is disabled.",
                       "Remove disabled rules that are no longer needed to keep the rulebase clean.")
            continue
        is_allow = r.action.lower() == "allow"

        if is_allow and set(r.source) & _ANY and set(r.destination) & _ANY \
                and set(r.application) & _ANY:
            result.add(Severity.HIGH, "any-any-rule", r.name,
                       "Allow rule matches any source, any destination, and any application.",
                       "Constrain at least one of source/destination/application; an any-any allow defeats segmentation.")

        if is_allow and not r.has_profiles:
            result.add(Severity.MEDIUM, "no-security-profiles", r.name,
                       "Allow rule has no Security Profiles (AV/AS/Vulnerability/URL/WildFire).",
                       "Attach a Security Profile Group so allowed traffic is inspected for threats.")

        if is_allow and not r.log_end and not r.log_setting:
            result.add(Severity.MEDIUM, "no-logging", r.name,
                       "Allow rule does not log at session end and has no log-forwarding profile.",
                       "Enable 'Log at Session End' and attach a Log Forwarding profile for visibility.")

        if is_allow and set(r.service) & _ANY and set(r.application) & _ANY:
            result.add(Severity.MEDIUM, "service-any", r.name,
                       "Allow rule uses service 'any' together with application 'any'.",
                       "Use application-default or specific services so the rule can't open unexpected ports.")

        if is_allow:
            enabled_allow.append(r)

    # Simple shadowing: an earlier allow rule with same zones that fully covers
    # a later rule's match criteria makes the later rule unreachable.
    for i, later in enumerate(enabled_allow):
        for earlier in enabled_allow[:i]:
            if (_covers(earlier.from_zones, later.from_zones)
                    and _covers(earlier.to_zones, later.to_zones)
                    and _covers(earlier.source, later.source)
                    and _covers(earlier.destination, later.destination)
                    and _covers(earlier.application, later.application)
                    and _covers(earlier.service, later.service)):
                result.add(Severity.HIGH, "shadowed-rule", later.name,
                           f"Rule is shadowed by earlier rule '{earlier.name}' and will never match.",
                           f"Reorder or narrow '{earlier.name}', or remove '{later.name}' if redundant.")
                break

    return result
