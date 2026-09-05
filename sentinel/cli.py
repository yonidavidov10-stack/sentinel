"""
cli.py
------
    sentinel run <project>            audit one project
    sentinel run --all <dir>          audit every project under <dir>
    sentinel init <project>           write a starter SENTINEL.toml

Exit codes: 0 clean · 1 something failed · 2 something could not be checked.
The third code exists so a scheduler can tell "it is broken" apart from "I
could not look", which are different problems with different fixes.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import manifest as mf
from . import history
from .checks import health, intent, security
from .report import Audit, to_dict, to_markdown, to_terminal

CHECKS = {"intent": intent.check, "security": security.check, "health": health.check}

STARTER = '''# What this project is, and what it promises to do.
# `sentinel run .` checks the promises below and tells you which still hold.

[project]
name = "{name}"
purpose = """
One or two sentences: what this project is FOR. Not how it works — what
would be lost if it stopped.
"""

[commands]
# How to run the suite, and a floor below the real count. The floor matters:
# most runners exit 0 when they collect nothing.
tests = "python -m pytest tests -q"
min_tests = 1

# Each expectation is a promise this project makes, in plain language, plus a
# mechanical way to find out whether it still holds. Write the ones that would
# hurt if they quietly stopped being true.
[[expectations]]
id = "example"
says = "The thing this project exists to do still happens"
why = "Replace this with the reason it matters when it stops"
kind = "command"
severity = "critical"
run = "echo replace-me"
expect_exit = 0
'''


def _audit(root: Path, only: list[str] | None) -> Audit:
    m = mf.load(root)
    audit = Audit(manifest=m)
    for name, fn in CHECKS.items():
        if only and name not in only:
            continue
        audit.results.append(fn(m))
    return audit


def _notify(audits: list[Audit], heartbeat: bool) -> None:
    """Send what is actionable. Never changes the exit code.

    A failure to REPORT is not a failure of the audit, and letting it become
    one would mean a Telegram outage marks a healthy project as broken.
    """
    import os

    from .notify import telegram
    from .verdict import Verdict

    token = os.environ.get("BUGFIXER_BOT_TOKEN", "")
    chats = [c.strip() for c in
             os.environ.get("BUGFIXER_CHAT_IDS", "").split(",") if c.strip()]
    if not token or not chats:
        print("(--telegram: BUGFIXER_BOT_TOKEN / BUGFIXER_CHAT_IDS not set — "
              "nothing sent)", file=sys.stderr)
        return

    for audit in audits:
        message = telegram.format_audit(audit)
        if message is None:
            if not heartbeat:
                # Nothing sent means nothing to remember. The history is a
                # record of what the OWNER was told, not of every audit that
                # ran — a silent audit told them nothing.
                continue
            message = telegram.format_heartbeat(audit, clean_days=7)
        result = telegram.send(message, token, chats)
        status = "sent" if result.ok else f"FAILED: {result.detail}"
        print(f"(telegram: {audit.manifest.name} — {status}, "
              f"{result.messages_sent} message(s))", file=sys.stderr)
        if result.ok:
            note = history.record(audit, message)
            if note:
                print(f"(history: {note})", file=sys.stderr)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="sentinel", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    r = sub.add_parser("run", help="audit a project")
    r.add_argument("path", nargs="?", default=".")
    r.add_argument("--all", action="store_true",
                   help="audit every project with a SENTINEL.toml underneath")
    r.add_argument("--format", choices=("terminal", "markdown", "json"),
                   default="terminal")
    r.add_argument("--out", type=Path, help="write the report here as well")
    r.add_argument("--only", action="append",
                   choices=sorted(CHECKS), help="run only these checks")
    r.add_argument("--telegram", action="store_true",
                   help="send actionable findings to Telegram. Reads "
                        "BUGFIXER_BOT_TOKEN and BUGFIXER_CHAT_IDS from the "
                        "environment; never takes them on the command line, "
                        "where they would land in shell history and CI logs.")
    r.add_argument("--heartbeat", action="store_true",
                   help="with --telegram, send an all-clear even when there is "
                        "nothing wrong. Meant for one day a week: a bot that "
                        "only ever speaks about problems is indistinguishable "
                        "from a bot that has stopped running.")

    i = sub.add_parser("init", help="write a starter SENTINEL.toml")
    i.add_argument("path", nargs="?", default=".")

    args = ap.parse_args(argv)

    if args.cmd == "init":
        root = Path(args.path).resolve()
        target = root / mf.MANIFEST_NAME
        if target.exists():
            print(f"{target} already exists — not overwriting.", file=sys.stderr)
            return 1
        target.write_text(STARTER.format(name=root.name), encoding="utf-8")
        print(f"Wrote {target}. Replace the example expectation with a real one.")
        return 0

    root = Path(args.path).resolve()
    roots = mf.discover(root) if args.all else [root]
    if not roots:
        print(f"No {mf.MANIFEST_NAME} found under {root}. "
              f"Run `sentinel init <project>` first.", file=sys.stderr)
        return 2

    audits: list[Audit] = []
    worst = 0
    for project_root in roots:
        try:
            audit = _audit(project_root, args.only)
        except mf.ManifestError as e:
            # A manifest that cannot be read is an UNCHECKED project, and the
            # exit code has to say so rather than passing over it.
            print(f"{project_root}: {e}", file=sys.stderr)
            worst = max(worst, 2)
            continue
        audits.append(audit)
        worst = max(worst, audit.exit_code)

    if args.format == "json":
        text = json.dumps([to_dict(a) for a in audits], indent=2, ensure_ascii=False)
    elif args.format == "markdown":
        text = "\n\n".join(to_markdown(a) for a in audits)
    else:
        text = "\n".join(to_terminal(a) for a in audits)

    print(text)

    if args.telegram:
        _notify(audits, heartbeat=args.heartbeat)

    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(
            "\n\n".join(to_markdown(a) for a in audits)
            if args.out.suffix == ".md" else text, encoding="utf-8")
    return worst


if __name__ == "__main__":
    raise SystemExit(main())
