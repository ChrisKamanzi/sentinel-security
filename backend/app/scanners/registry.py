"""Scanner registry and pipeline order.

To add a scanner: implement it (see base.py) and add it to SCANNERS. Its
position in the pipeline comes from PIPELINE_ORDER.
"""

import shutil
from dataclasses import dataclass
from functools import lru_cache

from app.scanners.base import BaseScanner
from app.scanners.ffuf import FfufScanner
from app.scanners.nmap import NmapScanner
from app.scanners.nuclei import NucleiScanner
from app.scanners.process import SAFE_PATH
from app.scanners.zap import ZapScanner

# Every tool in the planned workflow: name -> (display name, executable)
KNOWN_TOOLS: dict[str, tuple[str, str]] = {
    "nmap": ("Nmap", "nmap"),
    "ffuf": ("FFUF", "ffuf"),
    "nuclei": ("Nuclei", "nuclei"),
    "zap": ("OWASP ZAP", "docker"),  # runs the zaproxy/zap-stable image
}
PIPELINE_ORDER = ["nmap", "ffuf", "nuclei", "zap"]

# Scanners that are implemented and may be selected.
SCANNERS: dict[str, type[BaseScanner]] = {
    NmapScanner.name: NmapScanner,
    FfufScanner.name: FfufScanner,
    NucleiScanner.name: NucleiScanner,
    ZapScanner.name: ZapScanner,
}


@dataclass
class ToolStatus:
    name: str
    display_name: str
    implemented: bool
    available: bool
    path: str | None
    version: str | None


@lru_cache(maxsize=16)
def _cached_version(name: str, path: str) -> str | None:
    cls = SCANNERS.get(name)
    return cls.version(path) if cls else None


def tool_statuses() -> list[ToolStatus]:
    statuses = []
    for name in PIPELINE_ORDER:
        display, executable = KNOWN_TOOLS[name]
        cls = SCANNERS.get(name)
        path = cls.locate() if cls else shutil.which(executable, path=SAFE_PATH)
        statuses.append(ToolStatus(
            name=name,
            display_name=display,
            implemented=cls is not None,
            available=path is not None,
            path=path,
            version=_cached_version(name, path) if path else None,
        ))
    return statuses


def order_scanners(names: list[str]) -> list[str]:
    """Deduplicate and sort selected scanners into pipeline order."""
    unique = set(names)
    return [n for n in PIPELINE_ORDER if n in unique]
