"""
security.py
-----------
The holes that actually cost people: secrets committed to a repo, and a few
patterns that turn a bug into a breach.

DELIBERATELY NARROW. A scanner that cries wolf gets muted, and a muted scanner
is worse than none because it looks like coverage. So it checks TRACKED files
only — what git actually carries is what leaks — and every pattern here is one
with a low false-positive rate and a real consequence.
"""

from __future__ import annotations

import re
from pathlib import Path

from ..manifest import Manifest
from ..verdict import CheckResult, Finding, Severity, Verdict
from .base import run, timer

NAME = "security"

# Shapes that are almost never anything but a live credential.
SECRET_PATTERNS = [
    (r"sk-ant-[A-Za-z0-9_\-]{20,}", "Anthropic API key"),
    (r"sk-[A-Za-z0-9]{32,}", "OpenAI-style API key"),
    (r"gh[pousr]_[A-Za-z0-9]{30,}", "GitHub token"),
    (r"github_pat_[A-Za-z0-9_]{30,}", "GitHub fine-grained PAT"),
    (r"AKIA[0-9A-Z]{16}", "AWS access key id"),
    (r"\b[0-9]{8,10}:AA[A-Za-z0-9_\-]{30,}", "Telegram bot token"),
    (r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----", "private key"),
    (r"xox[baprs]-[A-Za-z0-9\-]{10,}", "Slack token"),
]

# Files that should never be tracked, whatever else is going on.
NEVER_TRACK = [".env", ".env.local", ".env.production", "secrets.toml",
               ".streamlit/secrets.toml", "id_rsa", "credentials.json",
               "service-account.json"]

# Code patterns with a real consequence. Each carries WHY, because a finding
# whose reason a reader has to guess gets dismissed.
RISKY_CODE = [
    (r"\beval\s*\(", "eval() executes whatever reaches it", Severity.HIGH),
    (r"\bexec\s*\(", "exec() executes whatever reaches it", Severity.HIGH),
    (r"pickle\.loads?\s*\(", "pickle deserialisation is arbitrary code execution",
     Severity.HIGH),
    (r"verify\s*=\s*False", "TLS verification disabled — the connection is "
     "encrypted but unauthenticated, so it can be intercepted", Severity.HIGH),
    (r"debug\s*=\s*True", "a debug server exposes an interactive console",
     Severity.MEDIUM),
    (r"host\s*=\s*[\"']0\.0\.0\.0[\"']", "binds every interface, not just "
     "localhost", Severity.MEDIUM),
]

TEXT_SUFFIXES = {".py", ".js", ".ts", ".jsx", ".tsx", ".sh", ".bash", ".zsh",
                 ".yml", ".yaml", ".toml", ".json", ".md", ".txt", ".cfg",
                 ".ini", ".env", ".html", ".css", ".sql", ".rb", ".go", ".rs"}


def _tracked_files(root: Path) -> tuple[list[Path], str]:
    """Files git actually carries. Returns ([], reason) when git cannot answer."""
    r = run("git ls-files -z", root, timeout_s=60)
    if r.error or not r.ok:
        return [], (r.error or r.output or "git ls-files failed")
    names = [n for n in r.stdout.split("\0") if n]
    return [root / n for n in names], ""


def check(m: Manifest) -> CheckResult:
    findings: list[Finding] = []
    root = m.root
    allow = set(m.security.get("allow_patterns") or [])

    with timer() as t:
        files, why_not = _tracked_files(root)
        if why_not:
            findings.append(Finding(
                check=NAME, title="Tracked files can be enumerated",
                verdict=Verdict.UNKNOWN, severity=Severity.HIGH,
                detail=f"could not list tracked files: {why_not}",
                remedy="Run sentinel inside a git repository."))
            return CheckResult(name=NAME, findings=findings, duration_s=t.seconds)

        # 1. Files that must never be tracked.
        tracked_names = {str(p.relative_to(root)) for p in files}
        leaked = sorted(n for n in tracked_names
                        if n in NEVER_TRACK or Path(n).name in NEVER_TRACK)
        if leaked:
            findings.append(Finding(
                check=NAME, title="No secret-bearing file is tracked by git",
                verdict=Verdict.FAIL, severity=Severity.CRITICAL,
                detail=f"{len(leaked)} file(s) that should never be committed",
                evidence="\n".join(leaked),
                remedy="git rm --cached <file>, add it to .gitignore, and "
                       "ROTATE whatever it contained — it is in the history."))
        else:
            findings.append(Finding(
                check=NAME, title="No secret-bearing file is tracked by git",
                verdict=Verdict.PASS, severity=Severity.CRITICAL,
                detail=f"{len(files)} tracked files, none of them .env or a key"))

        # 2. Secret-shaped strings inside tracked files.
        hits: list[str] = []
        for f in files:
            if f.suffix.lower() not in TEXT_SUFFIXES:
                continue
            try:
                text = f.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            for lineno, line in enumerate(text.splitlines(), 1):
                if any(a in line for a in allow):
                    continue
                for pattern, what in SECRET_PATTERNS:
                    if re.search(pattern, line):
                        rel = f.relative_to(root)
                        # The finding names the file and the KIND, never the
                        # value: a report that quotes the secret leaks it again,
                        # into wherever the report goes.
                        hits.append(f"{rel}:{lineno}: {what}")
                        break
        if hits:
            findings.append(Finding(
                check=NAME, title="No credential is committed in the source",
                verdict=Verdict.FAIL, severity=Severity.CRITICAL,
                detail=f"{len(hits)} credential-shaped string(s) in tracked files",
                evidence="\n".join(sorted(set(hits))[:20]),
                remedy="Remove it, rotate the credential, and move it to an "
                       "environment variable or a secret store. Assume it is "
                       "compromised: it is in the git history."))
        else:
            findings.append(Finding(
                check=NAME, title="No credential is committed in the source",
                verdict=Verdict.PASS, severity=Severity.CRITICAL,
                detail="no credential-shaped strings in tracked text files"))

        # 3. .gitignore covers the usual suspects.
        gi = root / ".gitignore"
        if not gi.is_file():
            findings.append(Finding(
                check=NAME, title=".gitignore protects the usual secret paths",
                verdict=Verdict.WARN, severity=Severity.MEDIUM,
                detail="there is no .gitignore",
                remedy="Add one covering .env, secrets, and virtualenvs."))
        else:
            body = gi.read_text(encoding="utf-8", errors="ignore")
            missing = [p for p in (".env", "*.pem", "secrets")
                       if p not in body]
            if missing:
                findings.append(Finding(
                    check=NAME, title=".gitignore protects the usual secret paths",
                    verdict=Verdict.WARN, severity=Severity.MEDIUM,
                    detail=f"not covered: {', '.join(missing)}",
                    evidence=str(gi.relative_to(root)),
                    remedy="Add those lines to .gitignore."))
            else:
                findings.append(Finding(
                    check=NAME, title=".gitignore protects the usual secret paths",
                    verdict=Verdict.PASS, severity=Severity.MEDIUM,
                    detail="covers .env, keys and secrets"))

        # 4. Risky code patterns.
        risky: dict[Severity, list[str]] = {}
        for f in files:
            if f.suffix.lower() not in {".py", ".js", ".ts", ".sh"}:
                continue
            try:
                text = f.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            for lineno, line in enumerate(text.splitlines(), 1):
                stripped = line.strip()
                # Comments and docstring prose describe these patterns far more
                # often than code uses them; flagging prose is how a scanner
                # earns its way into a mute filter.
                if stripped.startswith(("#", "//", "*", '"""', "'''")):
                    continue
                if any(a in line for a in allow):
                    continue
                for pattern, why, sev in RISKY_CODE:
                    if re.search(pattern, line):
                        risky.setdefault(sev, []).append(
                            f"{f.relative_to(root)}:{lineno}: {why}")
                        break
        if risky:
            worst = min(risky, key=lambda s: s.rank)
            flat = [x for sev in sorted(risky, key=lambda s: s.rank)
                    for x in risky[sev]]
            findings.append(Finding(
                check=NAME, title="No high-risk code patterns in tracked source",
                verdict=Verdict.WARN, severity=worst,
                detail=f"{len(flat)} occurrence(s) worth a human's eye",
                evidence="\n".join(flat[:15]),
                remedy="Each may be fine in context — confirm, then add it to "
                       "[security].allow_patterns in the manifest to silence it."))
        else:
            findings.append(Finding(
                check=NAME, title="No high-risk code patterns in tracked source",
                verdict=Verdict.PASS, severity=Severity.MEDIUM,
                detail="none found"))

    return CheckResult(name=NAME, findings=findings, duration_s=t.seconds)
