"""The single place where external tools are executed.

Safety properties:
* argv list only, ``shell=False`` -- no shell parsing, no string commands.
* argv[0] must be an absolute path to an executable (no PATH lookups here).
* Minimal environment with a fixed PATH; the app's secrets are not inherited.
* stdin is /dev/null, so a tool can never block waiting for input.
* Hard timeout; on expiry the whole process group is killed.
* Captured output is capped at ``max_output_bytes`` while it streams.

Optional streaming hooks (used for live progress):
* ``on_line(stream, line)`` is called from a reader thread for every output
  line. It must be quick and thread-safe (e.g. store the latest value).
* ``on_tick()`` is called from the calling thread every ``tick_seconds`` while
  the tool runs -- the safe place to touch the database.
"""

import os
import signal
import subprocess
import threading
import time
from dataclasses import dataclass
from typing import Callable, IO

SAFE_PATH = "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"
STDERR_CAP = 256_000
# The only variables a scanner may override, and only with absolute paths.
# Used to give a tool a throwaway HOME/config dir (e.g. FFUF writes history
# under $XDG_CONFIG_HOME/ffuf) so it never reads or writes the user's own.
ENV_OVERRIDE_ALLOWLIST = frozenset({"HOME", "XDG_CONFIG_HOME"})


@dataclass
class ProcessResult:
    argv: list[str]
    exit_code: int | None
    stdout: str
    stderr: str
    timed_out: bool
    duration_seconds: float
    truncated: bool


def _minimal_env(overrides: dict[str, str] | None = None) -> dict[str, str]:
    env = {
        "PATH": SAFE_PATH,
        "HOME": os.environ.get("HOME", "/tmp"),
        "LANG": "en_US.UTF-8",
        "LC_ALL": "en_US.UTF-8",
    }
    for key, value in (overrides or {}).items():
        if key not in ENV_OVERRIDE_ALLOWLIST:
            raise ValueError(f"environment override not allowed: {key!r}")
        if not isinstance(value, str) or "\x00" in value or not os.path.isabs(value):
            raise ValueError(f"environment override {key} must be an absolute path")
        env[key] = value
    return env


def _kill_process_group(proc: subprocess.Popen) -> None:
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        proc.kill()


class _Collector(threading.Thread):
    """Reads a stream line by line, keeping at most `limit` bytes."""

    def __init__(self, stream: IO[bytes], name: str, limit: int,
                 on_line: Callable[[str, str], None] | None):
        super().__init__(daemon=True)
        self.stream, self.stream_name, self.limit, self.on_line = stream, name, limit, on_line
        self.buffer = bytearray()
        self.truncated = False

    def run(self) -> None:
        for raw in iter(self.stream.readline, b""):
            room = self.limit - len(self.buffer)
            if room > 0:
                self.buffer += raw[:room]
            if len(raw) > room:
                self.truncated = True
            if self.on_line is not None:
                try:
                    self.on_line(self.stream_name, raw.decode("utf-8", errors="replace").rstrip("\n"))
                except Exception:  # a progress parser must never break the scan
                    pass
        self.stream.close()

    def text(self) -> str:
        return self.buffer.decode("utf-8", errors="replace")


def run_tool(
    argv: list[str],
    timeout: float,
    max_output_bytes: int,
    on_line: Callable[[str, str], None] | None = None,
    on_tick: Callable[[], None] | None = None,
    tick_seconds: float = 2.0,
    env_overrides: dict[str, str] | None = None,
) -> ProcessResult:
    if not argv or not all(isinstance(a, str) for a in argv):
        raise ValueError("argv must be a non-empty list of strings")
    if not os.path.isabs(argv[0]) or not os.access(argv[0], os.X_OK):
        raise ValueError(f"executable must be an absolute, executable path: {argv[0]!r}")
    env = _minimal_env(env_overrides)  # validates overrides before anything runs

    start = time.monotonic()
    proc = subprocess.Popen(
        argv,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
        shell=False,
        start_new_session=True,  # own process group, so we can kill children
    )
    out = _Collector(proc.stdout, "stdout", max_output_bytes, on_line)
    err = _Collector(proc.stderr, "stderr", STDERR_CAP, on_line)
    out.start()
    err.start()

    timed_out = False
    deadline = start + timeout
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            timed_out = True
            _kill_process_group(proc)
            proc.wait()
            break
        try:
            proc.wait(timeout=min(tick_seconds, remaining))
            break
        except subprocess.TimeoutExpired:
            if on_tick is not None:
                on_tick()

    out.join(timeout=5)
    err.join(timeout=5)
    return ProcessResult(
        argv=list(argv),
        exit_code=None if timed_out else proc.returncode,
        stdout=out.text(),
        stderr=err.text(),
        timed_out=timed_out,
        duration_seconds=round(time.monotonic() - start, 3),
        truncated=out.truncated or err.truncated,
    )
