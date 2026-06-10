"""
KB trigger pinning tests.

These tests pin behaviour against a class of bugs where overly-generic trigger
phrases in `_KB_TRIGGER_MAP` cause `_kb_match` to fire on unrelated questions,
which then short-circuits the chat handler into dumping a 30-80 KB KB article
into the response instead of letting the model answer.

Two assertion shapes:
  * _kb_match positives  — sentences a real user would ask must still route to
    the expected KB.
  * _kb_match negatives  — sentences that historically false-positived (or
    obviously have nothing to do with the article) must NOT trigger.

Run from the `local/` directory:  pytest tests/test_kb_triggers.py
"""

from app import _kb_match, _kb_relevant_sections


# ---------------------------------------------------------------------------
# Positives — legitimate questions must still route to the right KB.
# Regression guard: if a fix accidentally strips a useful trigger, fail here.
# ---------------------------------------------------------------------------

POSITIVE_CASES = [
    # (question, expected kb_id)
    ("My Panorama commit fails with an object reference error",  "KB-PAN-MGMT-001"),
    ("How do I push a device group to two firewalls at once?",   "KB-PAN-MGMT-001"),
    ("Template stack precedence is confusing me",                "KB-PAN-MGMT-001"),
    ("SSL forward proxy is breaking certificate pinning",        "KB-PAN-DEC-001"),
    ("Encrypted ClientHello bypassing my decryption",            "KB-PAN-DEC-001"),
    ("IKEv2 tunnel up but no traffic passes",                    "KB-PAN-VPN-001"),
    ("IKE phase 1 negotiation failing with Cisco ASA",           "KB-PAN-VPN-001"),
    ("HA pair stuck in initial state after upgrade",             "KB-PAN-HA-001"),
    ("PAN firewall failover not happening on link down",         "KB-PAN-HA-001"),
    ("App-ID showing unknown-tcp for a known SaaS app",          "KB-PAN-APPID-001"),
    ("User-ID mapping missing for GlobalProtect users",          "KB-SEC-UID-001"),
    ("U-turn NAT not working for internal users",                "KB-PAN-NAT-001"),
    ("Cortex XDR alert grouping is over-merging incidents",      "KB-CORTEX-XDR-001"),
    ("Cloud Identity Engine activation failing",                 "KB-CORTEX-XDR-001"),
    ("Prisma Access service connection BGP not established",     "KB-PA-ROUTING-001"),
    ("AIOps telemetry not uploading to Strata Cloud Manager",    "KB-SCM-AIOPS-0001"),
    ("GlobalProtect always pre-logon machine cert setup",        "KB-GP-PRELOGON-001"),
]


# ---------------------------------------------------------------------------
# Negatives — questions that must NOT trigger any KB short-circuit.
# Each comment names the offending trigger that historically matched.
# ---------------------------------------------------------------------------

NEGATIVE_CASES = [
    # --- bare "ike" used to match inside "like", "bike", "spike" -----------
    "I'd like to understand how App-ID classifies SaaS apps",
    "What does a spike in session count usually indicate?",
    "Looks like the dataplane CPU is pegged — what next?",

    # --- bare "cie" used to match inside "efficient", "society", "ancient",
    # "specie", "agencies", "policies" --------------------------------------
    "What's the most efficient way to audit a 3000-rule base?",
    "Can policies be reordered without a commit?",
    "Are there agencies that publish PAN-OS hardening baselines?",

    # --- bare "ech" used to match inside "echo", "speech", "reach", "search",
    # "fetch" ---------------------------------------------------------------
    "How do I echo the candidate config to a file?",
    "How do I search traffic logs for a specific source IP?",
    "Can the firewall reach an external DNS over a service route?",

    # --- bare "high availability" / "failover" matched generic HA topics ---
    "Should I deploy Postgres with high availability behind the firewall?",
    "Our Kubernetes ingress failover keeps flapping — is the firewall to blame?",

    # --- bare "phase 1" / "phase 2" matched project-management phases -----
    "We're in phase 1 of the migration — when should we cut traffic over?",
    "Phase 2 of the rollout is delayed by a week",

    # --- bare "forward proxy" matched non-Palo proxy questions ------------
    "Should we deploy a Squid forward proxy in front of the firewall?",

    # --- bare "certificate chain" / "cert chain" matched generic TLS ------
    "My nginx is serving an incomplete certificate chain to clients",
    "How do I inspect a cert chain with openssl s_client?",

    # --- bare "http/3" / "http3" matched generic protocol discussion ------
    "Does the new website support HTTP/3 over QUIC end-to-end?",

    # --- bare "commit lock" / "config lock" matched standalone-firewall ---
    "How do I clear a commit lock on a single firewall, not Panorama?",
    "Who has the configuration lock on the active firewall?",

    # --- bare "two stage commit" matched database two-phase commit etc. ---
    "Explain the two-stage commit protocol in distributed databases",
    "Is commit-then-push the same as a git push?",

    # --- bare "escalation checklist" / "har file" / "devtools network" ----
    "Is there a generic escalation checklist for SOC analysts?",
    "How do I open a HAR file in browser devtools?",

    # --- Completely unrelated questions — sanity floor --------------------
    "What's the weather like in Albany today?",
    "Write me a Python script to sort a list of dicts by key",
    "Explain the OSI model in three sentences",
]


def _trigger_match(message: str) -> str:
    """Return the matching trigger phrase from the picked KB, or '' if none."""
    entry = _kb_match(message)
    if not entry:
        return ""
    msg = message.lower()
    for phrase in entry["triggers"]:
        if phrase in msg:
            return phrase
    return ""


def _would_short_circuit(message: str):
    """Mirror the chat handler: a KB short-circuit fires only when _kb_match
    returns an entry AND _kb_relevant_sections returns non-None content.
    Returns the entry on short-circuit, else None.
    """
    entry = _kb_match(message)
    if not entry:
        return None
    if _kb_relevant_sections(entry, message) is None:
        return None
    return entry


def test_positive_cases_route_to_expected_kb():
    """Real user questions must still resolve to the correct KB."""
    failures = []
    for question, expected_kb_id in POSITIVE_CASES:
        entry = _kb_match(question)
        actual = entry["kb_id"] if entry else None
        if actual != expected_kb_id:
            failures.append(
                f"  {question!r}\n"
                f"    expected: {expected_kb_id}\n"
                f"    got:      {actual}"
            )
    assert not failures, (
        "Positive KB routing regressions:\n" + "\n".join(failures)
    )


def test_negative_cases_do_not_short_circuit():
    """Questions unrelated (or only tangentially related) to any KB must not
    cause the chat handler to short-circuit into a KB dump.

    This pins the full two-layer defense:
      Layer 1: _kb_match — does any trigger phrase appear?
      Layer 2: _kb_relevant_sections — does the question share enough
               vocabulary with the article body to warrant serving it?

    A leak here means BOTH layers let an unrelated question through. Either
    tighten the offending trigger, or strengthen the relevance check.
    """
    leaks = []
    for question in NEGATIVE_CASES:
        entry = _would_short_circuit(question)
        if entry is not None:
            phrase = _trigger_match(question)
            leaks.append(
                f"  {question!r}\n"
                f"    would dump KB {entry['kb_id']} via trigger {phrase!r}"
            )
    assert not leaks, (
        "KB short-circuit false positives — these questions should fall "
        "through to the model:\n" + "\n".join(leaks)
    )


def test_relevant_sections_returns_none_when_signal_is_weak():
    """Pin the second-line defense: when only one keyword from the question
    appears anywhere in the article (max_score == 1), the function must
    return None so the chat handler falls through to the model rather than
    dumping the full article.

    Constructed against a synthetic kb_entry so the assertion is independent
    of real KB content drift.
    """
    fake_entry = {
        "kb_id": "TEST-KB-001",
        "content": "full article content used as a fallback",
        "sections": [
            {"heading": "Setup",  "level": 2, "body": "## Setup\nalpha bravo charlie"},
            {"heading": "Tuning", "level": 2, "body": "## Tuning\ndelta echo foxtrot"},
        ],
        "triggers": frozenset(),
    }

    # Only "alpha" appears in the article. Other words are noise.
    # max_score == 1 → must return None.
    assert _kb_relevant_sections(fake_entry, "alpha xylophone zebra") is None


def test_relevant_sections_returns_content_on_strong_match():
    """A well-scoped question that genuinely targets the article should
    receive sections, not None."""
    entry = _kb_match("Panorama commit failed with object reference error")
    assert entry is not None and entry["kb_id"] == "KB-PAN-MGMT-001"

    result = _kb_relevant_sections(
        entry,
        "Panorama commit failed because a security rule still references a "
        "deleted address object — how do I find and fix this?",
    )
    assert result is not None and len(result) > 0
