#!/usr/bin/env python3
"""
PAN Copilot backend integration for the known_issues_lookup tool (ADKCyber).

This is the glue between PAN Copilot's Anthropic Messages loop and the
known-issues lookup service (api_known_issues.py, POST /lookup). Drop this
module into PAN Copilot's backend and use it to:

  1. Get the tool definition for the Messages `tools` array (get_tool_definition).
  2. Dispatch a model tool_use block to the HTTP lookup and build the matching
     tool_result block (handle_tool_use / dispatch_tool_uses).

The lookup is a READ-ONLY operation against a local SQLite corpus. It never
touches firewall or Panorama configuration, so no dry_run gate is needed.

Configuration (.env):
  KNOWN_ISSUES_API_URL   Base URL of the lookup service. Default http://127.0.0.1:8088
  KNOWN_ISSUES_API_TIMEOUT  Per-request timeout in seconds. Default 10
  PAN_COPILOT_MODEL      Model id PAN Copilot runs on (example runner only).
  ANTHROPIC_API_KEY      Only needed for the __main__ end-to-end example.

ADKCyber. Author: Jack Miller.
"""

import json
import logging
import os
import re
from typing import Any, Dict, List, Optional

import requests
from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger("pan_copilot.known_issues_tool")

API_URL = os.getenv("KNOWN_ISSUES_API_URL", "http://127.0.0.1:8088").rstrip("/")
API_TIMEOUT = int(os.getenv("KNOWN_ISSUES_API_TIMEOUT", "10"))

TOOL_NAME = "known_issues_lookup"

# Accept 11.1.4, 11.1.4-h7, or a leading "PAN-OS " prefix. Mirrors the parser in
# known_issues_db.parse_panos_version so we reject junk before the HTTP call.
_VER_RE = re.compile(r"(?:PAN-?OS\s*)?\d+\.\d+\.\d+(?:-h\d+)?", re.IGNORECASE)

# Static fallback used if the service is unreachable when building the tools array.
# Kept in sync with api_known_issues.py GET /tool-schema.
_STATIC_TOOL_DEFINITION: Dict[str, Any] = {
    "name": TOOL_NAME,
    "description": (
        "Look up Palo Alto Networks issues that are fixed in a later release of the "
        "same PAN-OS train than the user's running version, meaning the bug is likely "
        "present in what they are running. Call after obtaining the user's exact version."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "version": {"type": "string", "description": "Running PAN-OS version, e.g. 11.1.2"},
            "query": {"type": "string", "description": "Short symptom description"},
            "limit": {"type": "integer", "default": 15},
        },
        "required": ["version"],
    },
}


class KnownIssuesLookupError(Exception):
    """Raised when the lookup service cannot be reached or returns an error."""


class KnownIssuesLookupClient:
    """Thin, production-safe HTTP client for the known-issues lookup service."""

    def __init__(self, base_url: str = API_URL, timeout: int = API_TIMEOUT):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "PAN-Copilot-KnownIssues/1.0"})

    # ----- validation -------------------------------------------------------
    @staticmethod
    def validate_version(version: str) -> str:
        """Return a cleaned version string or raise ValueError on junk input."""
        if not isinstance(version, str) or not _VER_RE.search(version):
            raise ValueError(f"Unparseable PAN-OS version: {version!r}")
        return version.strip()

    # ----- calls ------------------------------------------------------------
    def lookup(self, version: str, query: str = "", limit: int = 15) -> Dict[str, Any]:
        """
        POST /lookup and return the parsed result.

        Request body:  {"version": "11.1.2", "query": "tunnel drops", "limit": 15}
        Response shape: {
            "running_version": "11.1.2",
            "train": "11.1",
            "match_count": 3,
            "matches": [
                {"issue_id": "PAN-300548", "fixed_in": "11.1.13",
                 "component": "", "description": "...", "source_url": "https://..."}
            ],
            "advice": "Known issue match. Recommend upgrading to the listed fixed version."
        }
        """
        clean_version = self.validate_version(version)
        payload = {"version": clean_version, "query": (query or "").strip(), "limit": int(limit)}
        url = f"{self.base_url}/lookup"
        try:
            resp = self.session.post(url, json=payload, timeout=self.timeout)
        except requests.RequestException as exc:
            logger.error("known_issues_lookup transport error to %s: %s", url, exc)
            raise KnownIssuesLookupError(f"Lookup service unreachable: {exc}") from exc

        if resp.status_code == 400:
            # The service rejected the version. Surface a clean, model-friendly message.
            detail = _safe_detail(resp)
            logger.warning("Lookup rejected version %r: %s", clean_version, detail)
            return {
                "running_version": clean_version,
                "train": None,
                "match_count": 0,
                "matches": [],
                "advice": f"Could not parse the version provided ({detail}). Ask the user to confirm it.",
            }
        if resp.status_code != 200:
            logger.error("Lookup service HTTP %s: %s", resp.status_code, _safe_detail(resp))
            raise KnownIssuesLookupError(f"Lookup service returned HTTP {resp.status_code}")

        try:
            return resp.json()
        except ValueError as exc:
            raise KnownIssuesLookupError("Lookup service returned non-JSON body") from exc

    def fetch_tool_definition(self) -> Dict[str, Any]:
        """GET /tool-schema, falling back to the bundled static copy on failure."""
        url = f"{self.base_url}/tool-schema"
        try:
            resp = self.session.get(url, timeout=self.timeout)
            resp.raise_for_status()
            return resp.json()
        except (requests.RequestException, ValueError) as exc:
            logger.warning("Falling back to static tool definition (%s unreachable: %s)", url, exc)
            return dict(_STATIC_TOOL_DEFINITION)

    def health(self) -> Dict[str, Any]:
        resp = self.session.get(f"{self.base_url}/health", timeout=self.timeout)
        resp.raise_for_status()
        return resp.json()


# Module-level default client so callers can just import and dispatch.
_default_client: Optional[KnownIssuesLookupClient] = None


def get_client() -> KnownIssuesLookupClient:
    global _default_client
    if _default_client is None:
        _default_client = KnownIssuesLookupClient()
    return _default_client


def get_tool_definition(live: bool = True) -> Dict[str, Any]:
    """
    Return the Anthropic tool definition to place in the Messages `tools` array.

    live=True fetches GET /tool-schema (single source of truth) and falls back to
    the static copy if the service is down. live=False uses the static copy only.
    """
    if not live:
        return dict(_STATIC_TOOL_DEFINITION)
    return get_client().fetch_tool_definition()


def handle_tool_use(tool_use: Dict[str, Any]) -> Dict[str, Any]:
    """
    Turn a single Anthropic tool_use block into a tool_result block.

    `tool_use` is the content block emitted by the model, for example:
        {"type": "tool_use", "id": "toolu_...", "name": "known_issues_lookup",
         "input": {"version": "11.1.2", "query": "dataplane reboot"}}

    Returns a tool_result block ready to append to the next user turn:
        {"type": "tool_result", "tool_use_id": "toolu_...",
         "content": "<json string>", "is_error": false}
    """
    tool_use_id = tool_use.get("id", "")
    tool_input = tool_use.get("input", {}) or {}
    version = tool_input.get("version", "")
    query = tool_input.get("query", "")
    limit = tool_input.get("limit", 15)

    try:
        result = get_client().lookup(version, query, limit)
        return {
            "type": "tool_result",
            "tool_use_id": tool_use_id,
            "content": json.dumps(result),
            "is_error": False,
        }
    except (ValueError, KnownIssuesLookupError) as exc:
        logger.error("known_issues_lookup failed: %s", exc)
        return {
            "type": "tool_result",
            "tool_use_id": tool_use_id,
            "content": json.dumps({"error": str(exc), "match_count": 0, "matches": []}),
            "is_error": True,
        }


def dispatch_tool_uses(content_blocks: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Scan an assistant message's content blocks and resolve every known_issues_lookup
    tool_use into a tool_result. Other tool names are ignored (handle them elsewhere).
    """
    results = []
    for block in content_blocks:
        if block.get("type") == "tool_use" and block.get("name") == TOOL_NAME:
            results.append(handle_tool_use(block))
    return results


def _safe_detail(resp: requests.Response) -> str:
    try:
        body = resp.json()
        return body.get("detail", resp.text[:200])
    except ValueError:
        return resp.text[:200]


# ---------------------------------------------------------------------------
# End-to-end example: model -> tool_use -> /lookup -> tool_result -> answer.
# Run directly only as a smoke test. Requires ANTHROPIC_API_KEY and a running
# uvicorn api_known_issues:app on KNOWN_ISSUES_API_URL.
# ---------------------------------------------------------------------------
def _example() -> None:
    from anthropic import Anthropic

    model = os.getenv("PAN_COPILOT_MODEL", "claude-sonnet-4-6")
    client = Anthropic()
    tool_def = get_tool_definition(live=True)

    system = (
        "You are ADK Cyber AI. When a user reports a defect, ask for their exact "
        "PAN-OS version, then call known_issues_lookup before answering."
    )
    messages: List[Dict[str, Any]] = [
        {"role": "user", "content": "I'm on PAN-OS 11.1.2 and the dataplane reboots after a commit. Known bug?"}
    ]

    # First model turn: expect a tool_use for known_issues_lookup.
    resp = client.messages.create(
        model=model, max_tokens=1024, system=system, tools=[tool_def], messages=messages
    )
    print("stop_reason:", resp.stop_reason)

    # Convert SDK content blocks to plain dicts for the dispatcher.
    assistant_blocks = [b.model_dump() for b in resp.content]
    messages.append({"role": "assistant", "content": assistant_blocks})

    tool_results = dispatch_tool_uses(assistant_blocks)
    if not tool_results:
        print("Model did not call the tool. Final text:")
        print("".join(b.text for b in resp.content if getattr(b, "type", None) == "text"))
        return

    # Feed tool_result(s) back and let the model compose the recommendation.
    messages.append({"role": "user", "content": tool_results})
    final = client.messages.create(
        model=model, max_tokens=1024, system=system, tools=[tool_def], messages=messages
    )
    print("".join(b.text for b in final.content if getattr(b, "type", None) == "text"))


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    _example()
