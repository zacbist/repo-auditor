from typing import Optional

from pydantic import BaseModel, Field


class Finding(BaseModel):
    type: str
    severity: Optional[str] = None
    file: Optional[str] = None
    line: Optional[int] = None
    label: Optional[str] = None
    issue: Optional[str] = None
    package: Optional[str] = None
    source: Optional[str] = None
    version: Optional[str] = None
    size_mb: Optional[float] = None
    found: Optional[bool] = None


class AuditSummary(BaseModel):
    total: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0


class AuditReport(BaseModel):
    url: str
    branch: str
    head: str
    results: dict[str, list[Finding]] = Field(default_factory=dict)
    summary: AuditSummary = Field(default_factory=AuditSummary)
