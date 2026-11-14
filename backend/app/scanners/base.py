"""Common scanner interface.

Adding a scanner (Nuclei, FFUF, ZAP, ...) means: subclass ``BaseScanner``,
implement ``build_command`` and ``parse`` (or override ``run`` for API-driven
tools like ZAP), and register the class in ``registry.SCANNERS``. The
orchestrator, API, scope checks, persistence and deduplication are shared.
"""

import os
import shutil
import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Callable, ClassVar

from pydantic import BaseModel, ConfigDict

from app.core.config import settings
from app.models.finding import FindingSeverity
from app.scanners.process import SAFE_PATH, ProcessResult, run_tool


class ScannerError(Exception):
    """A scanner ran but failed. Carries whatever output was captured."""

    def __init__(self, message: str, process: ProcessResult | None = None):
        super().__init__(message)
        self.process = process


class ScannerUnavailable(ScannerError):
    """The scanner's executable could not be found."""


class EmptyOptions(BaseModel):
    model_config = ConfigDict(extra="forbid")


@dataclass
class ScanContext:
    """Everything a scanner may use. Built only after the scope check passed."""

    scan_id: uuid.UUID
    target_id: uuid.UUID
    host: str  # validated hostname/IP of the authorized target
    ips: list[str]  # scope-checked addresses; scanners must stay within these
    base_url: str | None
    target_url: str
    options: BaseModel
    # Artifacts from scanners that already completed in this assessment,
    # keyed by scanner name (e.g. previous["nmap"]["http_services"]).
    previous: dict[str, dict[str, Any]] = field(default_factory=dict)
    report_progress: Callable[[int], None] = lambda pct: None
    # Re-runs the full authorization + scope check (app.core.scope.authorize_scan)
    # from fresh database state and fresh DNS. Scanners call it immediately
    # before each tool execution. None outside the orchestrator (unit tests).
    revalidate: Callable[[], Any] | None = None


@dataclass
class NormalizedFinding:
    title: str
    severity: FindingSeverity
    # Stable identity of the issue for deduplication, e.g. "open-port:tcp/22".
    dedup_key: str
    location: str | None = None
    description: str | None = None
    recommendation: str | None = None
    evidence: str | None = None
    original_severity: str | None = None
    confidence: str | None = None
    source_id: str | None = None
    cwe: str | None = None
    references: list[str] = field(default_factory=list)


@dataclass
class ScannerOutput:
    findings: list[NormalizedFinding]
    artifacts: dict[str, Any]
    raw_output: str
    exit_code: int | None
    command: list[str]


class BaseScanner(ABC):
    name: ClassVar[str]
    display_name: ClassVar[str]
    executable_name: ClassVar[str]
    Options: ClassVar[type[BaseModel]] = EmptyOptions

    def __init__(self, executable_path: str):
        self.executable_path = executable_path

    # --- discovery ----------------------------------------------------------
    @classmethod
    def locate(cls) -> str | None:
        """Absolute path of the tool, from settings (<name>_path) or SAFE_PATH."""
        configured = getattr(settings, f"{cls.name}_path", "") or ""
        if configured:
            ok = os.path.isabs(configured) and os.access(configured, os.X_OK)
            return configured if ok else None
        return shutil.which(cls.executable_name, path=SAFE_PATH)

    @classmethod
    def version(cls, path: str) -> str | None:
        return None

    # --- execution ----------------------------------------------------------
    def timeout_seconds(self, ctx: ScanContext) -> int:
        return 600

    @abstractmethod
    def build_command(self, ctx: ScanContext) -> list[str]: ...

    @abstractmethod
    def parse(self, process: ProcessResult, ctx: ScanContext) -> ScannerOutput: ...

    def run(self, ctx: ScanContext) -> ScannerOutput:
        argv = self.build_command(ctx)
        process = run_tool(
            argv,
            timeout=self.timeout_seconds(ctx),
            max_output_bytes=settings.max_tool_output_bytes,
        )
        if process.timed_out:
            raise ScannerError(
                f"{self.display_name} timed out after {self.timeout_seconds(ctx)}s",
                process,
            )
        return self.parse(process, ctx)
