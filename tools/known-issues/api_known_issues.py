#!/usr/bin/env python3
"""
FastAPI service exposing the PAN known-issues lookup over HTTP.

PAN Copilot's backend calls POST /lookup as a tool during a conversation: the
model asks the user for their PAN-OS version, then sends {version, query} here and
gets back the known issues fixed in a later release of the same train.

Run:
    uvicorn api_known_issues:app --host 0.0.0.0 --port 8088

The Anthropic tool definition that maps to this endpoint is served at /tool-schema
so you can drop it straight into PAN Copilot's tools array.

ADKCyber. Author: Jack Miller.
"""

import os

from fastapi import APIRouter, FastAPI, HTTPException
from pydantic import BaseModel, Field

from known_issues_db import KnownIssuesDB, parse_panos_version

DB_PATH = os.getenv("KNOWN_ISSUES_DB", "known_issues.db")

app = FastAPI(title="PAN Copilot Known-Issues API", version="1.0.0")
router = APIRouter()


class LookupRequest(BaseModel):
    version: str = Field(..., description="Running PAN-OS version, for example 11.1.2 or 11.1.4-h7")
    query: str = Field("", description="Short description of the symptom")
    limit: int = Field(15, ge=1, le=50)


def _db() -> KnownIssuesDB:
    # One connection per request keeps SQLite access thread-safe under uvicorn.
    return KnownIssuesDB(DB_PATH)


@router.get("/health")
def health():
    db = _db()
    try:
        return {"status": "ok", **db.stats()}
    finally:
        db.close()


@router.post("/lookup")
def lookup(req: LookupRequest):
    if not parse_panos_version(req.version):
        raise HTTPException(status_code=400, detail=f"Unparseable version '{req.version}'")
    db = _db()
    try:
        result = db.search(req.version, req.query, req.limit)
    finally:
        db.close()
    result["advice"] = (
        "Known issue match. Recommend upgrading to the listed fixed version."
        if result.get("match_count")
        else "No known fixed issue matched. Treat as a possible new defect after review."
    )
    return result


@router.get("/stats")
def stats():
    db = _db()
    try:
        return db.stats()
    finally:
        db.close()


@router.get("/tool-schema")
def tool_schema():
    """Anthropic tool definition for wiring this endpoint into PAN Copilot."""
    return {
        "name": "known_issues_lookup",
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


app.include_router(router)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("api_known_issues:app", host="0.0.0.0", port=int(os.getenv("API_PORT", "8088")))
