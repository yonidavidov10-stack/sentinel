"""
telegram.py
-----------
Sends an audit to a Telegram bot.

WHEN IT SPEAKS, AND WHEN IT DOES NOT
------------------------------------
A bot that says "all clear" every morning becomes wallpaper within a week, and
then nobody reads the morning it is not clear. So the default is silence when
there is nothing actionable.

But silence has its own failure mode, and this project has already lived it:
the daily report stopped reaching Telegram on 2026-08-29 and nobody noticed for
three days, because a system that says nothing looks exactly like a system with
nothing to say. So a clean audit still speaks on a HEARTBEAT — once a week —
and the message says how many consecutive clean days it is reporting. A gap in
the heartbeat is then visible without anyone having to remember the schedule.

WHAT IT WILL NOT DO
-------------------
Quote a credential. The audit's evidence can contain the very secret-shaped
strings the security check found, and a report that repeats them leaks them
again into a chat log. Evidence is scrubbed before it is sent.
"""

from __future__ import annotations

import json
import re
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass

from ..report import Audit
from ..verdict import Severity, Verdict

API = "https://api.telegram.org"

# Telegram's hard limit is 4096. The margin absorbs the HTML entities that
# escaping adds after the split has already been decided.
LIMIT = 3900

SEND_RETRY_DELAYS = (5, 20, 60)

# Anything shaped like a credential, redacted before it can reach a chat log.
# The security check reports the KIND of secret it found, never the value, but
# a `command` expectation's stdout is arbitrary and can carry anything.
_REDACT = [
    (re.compile(r"\b\d{8,10}:AA[\w-]{30,}"), "‹telegram-token›"),
    (re.compile(r"sk-ant-[A-Za-z0-9_\-]{20,}"), "‹anthropic-key›"),
    (re.compile(r"gh[pousr]_[A-Za-z0-9]{30,}"), "‹github-token›"),
    (re.compile(r"github_pat_[A-Za-z0-9_]{30,}"), "‹github-pat›"),
    (re.compile(r"AKIA[0-9A-Z]{16}"), "‹aws-key›"),
    (re.compile(r"xox[baprs]-[A-Za-z0-9\-]{10,}"), "‹slack-token›"),
]


def scrub(text: str) -> str:
    for rx, replacement in _REDACT:
        text = rx.sub(replacement, text)
    return text


def _esc(text: str) -> str:
    """Telegram HTML needs exactly these three escaped."""
    return (text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"))


@dataclass
class SendResult:
    ok: bool
    detail: str = ""
    messages_sent: int = 0


def _split(text: str, limit: int = LIMIT) -> list[str]:
    """Split on paragraph boundaries so a section never breaks mid-sentence."""
    if len(text) <= limit:
        return [text]
    out, current = [], ""
    for block in text.split("\n\n"):
        candidate = f"{current}\n\n{block}" if current else block
        if len(candidate) <= limit:
            current = candidate
            continue
        if current:
            out.append(current)
        # A single block longer than the limit is cut on lines rather than
        # dropped — losing the tail of a finding silently is worse than a
        # slightly ugly break.
        while len(block) > limit:
            cut = block.rfind("\n", 0, limit)
            cut = cut if cut > limit // 2 else limit
            out.append(block[:cut])
            block = block[cut:].lstrip("\n")
        current = block
    if current:
        out.append(current)
    return out


def send(text: str, token: str, chat_ids: list[str]) -> SendResult:
    """Send to every chat. Never raises."""
    import time

    if not token or not chat_ids:
        return SendResult(False, "no token or no chat ids")

    chunks = _split(scrub(text))
    sent = 0
    for chat_id in chat_ids:
        for chunk in chunks:
            payload = urllib.parse.urlencode({
                "chat_id": chat_id,
                "text": chunk,
                "parse_mode": "HTML",
                "disable_web_page_preview": "true",
            }).encode()
            url = f"{API}/bot{token}/sendMessage"
            for attempt, delay in enumerate((0, *SEND_RETRY_DELAYS)):
                if delay:
                    time.sleep(delay)
                try:
                    with urllib.request.urlopen(url, data=payload, timeout=30) as r:
                        json.loads(r.read().decode())
                    sent += 1
                    break
                except urllib.error.HTTPError as e:
                    # Telegram refusing the message is not transient: a bad
                    # chat id or malformed HTML will be refused identically
                    # forever, and retrying just delays the report.
                    body = e.read().decode(errors="ignore")[:200]
                    return SendResult(False, f"HTTP {e.code}: {scrub(body)}", sent)
                except Exception as e:                    # noqa: BLE001
                    if attempt == len(SEND_RETRY_DELAYS):
                        return SendResult(False, f"{type(e).__name__}: {e}", sent)
    return SendResult(True, "", sent)


def format_audit(audit: Audit, clean_streak: int = 0) -> str | None:
    """The message, or None when there is nothing worth saying.

    None is the common case and it is deliberate. See the module docstring:
    the caller decides whether to override it for a heartbeat.
    """
    actionable = [f for f in audit.findings if f.verdict.is_actionable]
    if not actionable:
        return None

    by_verdict = {v: [f for f in actionable if f.verdict is v]
                  for v in (Verdict.FAIL, Verdict.UNKNOWN, Verdict.WARN)}

    # Name the SENDER as well as the subject. The first live message said only
    # "stock-predictor", which reads as a message from that project rather than
    # a bug report about it — and once several projects report here, the
    # distinction is the whole point of the line.
    L = [f"🛠 <b>Bug Fixer</b>({_esc(audit.manifest.name)})", ""]
    counts = []
    if by_verdict[Verdict.FAIL]:
        counts.append(f"❌ {len(by_verdict[Verdict.FAIL])} נשברו")
    if by_verdict[Verdict.UNKNOWN]:
        counts.append(f"❓ {len(by_verdict[Verdict.UNKNOWN])} לא נבדקו")
    if by_verdict[Verdict.WARN]:
        counts.append(f"⚠️ {len(by_verdict[Verdict.WARN])} לתשומת לב")
    L.append(" · ".join(counts))

    titles = {Verdict.FAIL: "❌ נשבר", Verdict.UNKNOWN: "❓ לא נבדק",
              Verdict.WARN: "⚠️ שווה מבט"}
    for verdict in (Verdict.FAIL, Verdict.UNKNOWN, Verdict.WARN):
        items = sorted(by_verdict[verdict],
                       key=lambda f: (Severity(f.severity).rank, f.title))
        if not items:
            continue
        L.append("")
        L.append(f"<b>{titles[verdict]}</b>")
        for f in items:
            L.append("")
            L.append(f"• <b>{_esc(f.say('title', 'he'))}</b>")
            detail = f.say("detail", "he")
            if detail:
                L.append(f"  {_esc(detail)}")
            # Evidence rides along only for genuine breakage. A warning with a
            # code dump attached is how a useful report becomes a wall of text.
            if verdict is Verdict.FAIL and f.evidence:
                snippet = "\n".join(f.evidence.strip().splitlines()[:4])
                L.append(f"  <code>{_esc(snippet[:300])}</code>")
            remedy = f.say("remedy", "he")
            if remedy:
                L.append(f"  ↳ {_esc(remedy)}")

    if by_verdict[Verdict.UNKNOWN]:
        L.append("")
        L.append("<i>❓ פירושו שאף אחד לא בדק — לא שהכול תקין.</i>")
    return "\n".join(L)


def format_heartbeat(audit: Audit, clean_days: int) -> str:
    """The weekly all-clear. Its job is to make a GAP visible."""
    return (f"🛠 <b>Bug Fixer</b>({_esc(audit.manifest.name)})\n\n"
            f"✅ נקי — {audit.count(Verdict.PASS)} בדיקות עברו.\n"
            f"{clean_days} ימים רצופים בלי ממצא.\n\n"
            f"<i>ההודעה הזו נשלחת פעם בשבוע כדי שתדע שהבודק חי. "
            f"שתיקה ארוכה ממנה היא עצמה סימן.</i>")
