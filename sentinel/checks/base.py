"""Shared plumbing for checks: running a command safely and timing a check."""

from __future__ import annotations

import os
import shlex
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path

# A command that hangs would hang the whole audit, and an audit that never
# finishes is an audit nobody runs.
DEFAULT_TIMEOUT_S = 300

# Enough to see what went wrong, bounded so one chatty command cannot make the
# report unreadable or the JSON enormous.
MAX_OUTPUT_CHARS = 4000


@dataclass
class Run:
    ok: bool
    exit_code: int | None
    stdout: str
    stderr: str
    timed_out: bool = False
    error: str = ""          # could not run at all -> the caller reports UNKNOWN

    @property
    def output(self) -> str:
        return (self.stdout + ("\n" + self.stderr if self.stderr else "")).strip()


def run(command: str, cwd: Path, timeout_s: int = DEFAULT_TIMEOUT_S,
        env_extra: dict | None = None) -> Run:
    """Run a shell command in `cwd`.

    TRUST BOUNDARY, stated plainly: commands come from the audited project's own
    SENTINEL.toml, and are executed with this process's privileges. That is the
    point — a project must be able to say how to verify itself — but it means a
    manifest is exactly as trusted as the repository containing it. Never run
    sentinel against a repo you would not run `make` in.

    Never raises. A command that cannot start is an UNKNOWN, not a crash: the
    auditor's job is to report what it could not check, not to fall over.
    """
    env = dict(os.environ)
    # Keeps unittest/pytest output parseable regardless of the terminal.
    env.setdefault("NO_COLOR", "1")
    env.setdefault("PYTHONUNBUFFERED", "1")

    # A project's virtualenv goes on PATH ahead of everything else, so a
    # manifest can just say `python -m pytest` and mean the right interpreter
    # in both places. Without this, a manifest has to choose: `python3` finds
    # the system interpreter locally (which has none of the project's
    # dependencies and reports the suite as broken), while `.venv/bin/python`
    # does not exist on a CI runner. Encoding that choice as shell conditionals
    # in every manifest is how a config format becomes a programming language.
    for venv in ("venv", ".venv"):
        bin_dir = Path(cwd) / venv / "bin"
        if bin_dir.is_dir():
            env["PATH"] = f"{bin_dir}{os.pathsep}{env.get('PATH', '')}"
            env["VIRTUAL_ENV"] = str(Path(cwd) / venv)
            break

    if env_extra:
        env.update({str(k): str(v) for k, v in env_extra.items()})

    try:
        p = subprocess.run(command, shell=True, cwd=str(cwd), env=env,
                           capture_output=True, text=True, timeout=timeout_s)
    except subprocess.TimeoutExpired:
        return Run(ok=False, exit_code=None, stdout="", stderr="",
                   timed_out=True,
                   error=f"timed out after {timeout_s}s")
    except (OSError, ValueError) as e:
        return Run(ok=False, exit_code=None, stdout="", stderr="",
                   error=f"{type(e).__name__}: {e}")

    return Run(ok=p.returncode == 0, exit_code=p.returncode,
               stdout=_clip(p.stdout), stderr=_clip(p.stderr))


def _clip(text: str) -> str:
    text = text or ""
    if len(text) <= MAX_OUTPUT_CHARS:
        return text
    half = MAX_OUTPUT_CHARS // 2
    return (text[:half] + f"\n… [{len(text) - MAX_OUTPUT_CHARS} chars elided] …\n"
            + text[-half:])


def which(binary: str) -> bool:
    from shutil import which as _w
    return _w(binary) is not None


class timer:
    """`with timer() as t: ...` then `t.seconds`."""

    def __enter__(self):
        self._t0 = time.time()
        return self

    def __exit__(self, *exc):
        self.seconds = time.time() - self._t0
        return False
