"""Migration report entries and aggregation."""

from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class Severity(str, Enum):
    AUTO = "auto"
    APPROXIMATION = "approximation"
    MANUAL_REQUIRED = "manual_required"
    BLOCKER = "blocker"


class ReportEntry(BaseModel):
    severity: Severity
    category: str
    message: str
    source_line: str | None = None
    pan_hint: str | None = None


class MigrationReport(BaseModel):
    source_format: str = "unknown"
    entries: list[ReportEntry] = Field(default_factory=list)
    unmapped_lines: list[str] = Field(default_factory=list)

    def add(
        self,
        severity: Severity,
        category: str,
        message: str,
        *,
        source_line: str | None = None,
        pan_hint: str | None = None,
    ) -> None:
        self.entries.append(
            ReportEntry(
                severity=severity,
                category=category,
                message=message,
                source_line=source_line,
                pan_hint=pan_hint,
            )
        )

    def summary(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for e in self.entries:
            counts[e.severity.value] = counts.get(e.severity.value, 0) + 1
        counts["unmapped_lines"] = len(self.unmapped_lines)
        return counts

    def to_dict(self) -> dict[str, Any]:
        return {
            "source_format": self.source_format,
            "summary": self.summary(),
            "entries": [e.model_dump() for e in self.entries],
            "unmapped_lines": self.unmapped_lines,
        }