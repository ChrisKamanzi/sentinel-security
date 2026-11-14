"""The safe subprocess runner, exercised with harmless local binaries."""

import pytest

from app.scanners.process import run_tool


def test_runs_argv_without_shell():
    # If a shell were involved, `;` would start a second command.
    result = run_tool(["/bin/echo", "hello; echo injected"], timeout=5, max_output_bytes=1000)
    assert result.exit_code == 0
    assert result.stdout.strip() == "hello; echo injected"
    assert not result.timed_out


def test_relative_executable_rejected():
    with pytest.raises(ValueError):
        run_tool(["echo", "x"], timeout=5, max_output_bytes=1000)


def test_non_string_args_rejected():
    with pytest.raises(ValueError):
        run_tool(["/bin/echo", 1], timeout=5, max_output_bytes=1000)  # type: ignore[list-item]


def test_timeout_kills_process():
    result = run_tool(["/bin/sleep", "10"], timeout=0.5, max_output_bytes=1000)
    assert result.timed_out
    assert result.exit_code is None
    assert result.duration_seconds < 5


def test_output_is_capped():
    result = run_tool(["/bin/echo", "x" * 500], timeout=5, max_output_bytes=100)
    assert len(result.stdout) == 100
    assert result.truncated


def test_environment_is_minimal(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "should-not-leak")
    result = run_tool(["/usr/bin/env"], timeout=5, max_output_bytes=10_000)
    assert "ANTHROPIC_API_KEY" not in result.stdout
    assert "PATH=" in result.stdout


def test_on_line_receives_both_streams():
    seen = []
    run_tool(["/bin/sh", "-c", "echo out; echo err 1>&2"], timeout=5,
             max_output_bytes=1000, on_line=lambda s, l: seen.append((s, l)))
    assert ("stdout", "out") in seen and ("stderr", "err") in seen


def test_on_tick_called_while_running():
    ticks = []
    run_tool(["/bin/sleep", "0.5"], timeout=5, max_output_bytes=100,
             on_tick=lambda: ticks.append(1), tick_seconds=0.1)
    assert len(ticks) >= 2


def test_broken_line_callback_does_not_break_run():
    def boom(stream, line):
        raise RuntimeError("parser bug")
    result = run_tool(["/bin/echo", "hi"], timeout=5, max_output_bytes=100, on_line=boom)
    assert result.exit_code == 0 and result.stdout.strip() == "hi"


# --- allowlisted environment overrides (used to isolate FFUF's config dir) -----------


def test_env_override_applied_for_allowlisted_keys(tmp_path):
    result = run_tool(["/usr/bin/env"], timeout=5, max_output_bytes=10_000,
                      env_overrides={"HOME": str(tmp_path), "XDG_CONFIG_HOME": str(tmp_path / ".config")})
    assert f"HOME={tmp_path}\n" in result.stdout
    assert f"XDG_CONFIG_HOME={tmp_path}/.config\n" in result.stdout


@pytest.mark.parametrize("overrides", [
    {"PATH": "/tmp"},
    {"LD_PRELOAD": "/tmp/evil.so"},
    {"DYLD_INSERT_LIBRARIES": "/tmp/evil.dylib"},
    {"HTTP_PROXY": "/tmp"},
    {"ANTHROPIC_API_KEY": "/tmp"},
])
def test_env_override_rejects_non_allowlisted_keys(overrides):
    with pytest.raises(ValueError, match="not allowed"):
        run_tool(["/usr/bin/env"], timeout=5, max_output_bytes=100, env_overrides=overrides)


@pytest.mark.parametrize("value", ["relative/dir", "", "/tmp/x\x00y"])
def test_env_override_requires_absolute_paths(value):
    with pytest.raises(ValueError, match="absolute path"):
        run_tool(["/usr/bin/env"], timeout=5, max_output_bytes=100, env_overrides={"HOME": value})


def test_env_override_keeps_environment_minimal(tmp_path, monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "should-not-leak")
    result = run_tool(["/usr/bin/env"], timeout=5, max_output_bytes=10_000,
                      env_overrides={"HOME": str(tmp_path)})
    assert "ANTHROPIC_API_KEY" not in result.stdout
    assert sorted(line.split("=", 1)[0] for line in result.stdout.splitlines()) == \
        ["HOME", "LANG", "LC_ALL", "PATH"]
