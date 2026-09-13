# The security model

Started 2026-09-13, deliberately as a foundation rather than a finished thing.
What is written here is what has been MEASURED across the owner's projects, not
a checklist copied from somewhere. Everything unmeasured is marked as such.

There are two threats, they need different machinery, and conflating them is
how a security programme becomes a list of ignored warnings.

---

## Threat 1 — someone else gets in

The classic one, and for these projects the smaller of the two.

### What was measured (2026-09-13)

| Surface | Finding |
|---|---|
| Secrets in source | Clean. Four checks already cover this. |
| Script injection into workflows | None. No `${{ github.event.* }}` reaches a `run:` block. |
| Workflow permissions | `contents: write` everywhere it appears, and every instance is needed — these workflows commit. No `write-all`, no `pull_request_target`. |
| Third-party actions | **Pinned to mutable tags** (`@v4`, `@v1`), not commit SHAs. |
| Dependencies | Unmeasured. Next. |

### The one real exposure: tags are not versions

`uses: actions/checkout@v4` does not name a version. It names a POINTER that
the action's owner can move at any time, to any commit. Whatever it points at
when a workflow runs executes inside the job — with `contents: write` and with
every secret that job holds.

For these repositories that means: the prediction database, the bot tokens, and
a Claude Code token that can read and write code.

All five actions in use are first-party (`actions/*`, `anthropics/*`), which is
a much smaller risk than a random community action. It is not zero, and the
industry has the incident reports to prove it.

**The fix is a SHA instead of a tag**, and the cost is real: pinned actions stop
receiving security patches, so something has to update them. That trade is a
decision, not a default, which is why it is written here rather than silently
applied.

---

## Threat 2 — we break it ourselves

The larger threat here, by a wide margin, and the one with the evidence.

In the four days to 2026-09-13, working carefully, with a test suite and an
auditor running twice a day, this happened:

* Two delivered Telegram messages were lost, and the run reported SUCCESS.
* A script deleted a `[security]` table nobody asked it to touch.
* Twelve compiled files sat tracked in a public repository behind an ignore
  rule that could not untrack them.
* A check passed for months while testing nothing at all, twice.

None of these was an attack. Every one was routine work by someone paying
attention. **A defence that only keeps strangers out defends against the rarer
half of the problem.**

### THE FINDING THAT MATTERS MOST

The irreplaceable asset of stock-predictor is its record:

```
predictions      70     months of real market outcomes
learned_lessons  44
daily_snapshots  14
sent_reports      9
```

**It cannot be regenerated.** Re-running the code does not reproduce it —
it is a record of what happened on particular days at particular prices. Lose
it and the system's entire track record resets to zero.

It exists in ONE PLACE: the GitHub repository. And:

* `main` **cannot be branch-protected** — private repo on a free plan, so the
  API refuses. Anything holding `contents: write` can force-push over history.
* Several automated workflows hold exactly that token, on a schedule, without
  a human present.
* There is no copy anywhere else.

So the single most valuable security control available is not a firewall. It is
**a second copy of that file, somewhere that a bad push cannot reach.**

### The principle

> Ask what cannot be undone, and what cannot be recreated. Defend those first,
> and defend them by making them recoverable rather than by trying to make
> mistakes impossible.

Mistakes are not made impossible. Four days of evidence says so.

---

## What this does NOT protect against

Stated plainly, because a security document that only lists strengths is
marketing.

* **A compromised Mac.** Every credential here is reachable from this laptop.
* **A compromised GitHub account.** The tokens live there.
* **The improvement pass making the predictions worse.** Its five guards prove
  it did not lie about its work. They say nothing about whether it was right.
* **Anything about dependencies.** Not yet measured.
* **Disk loss**, for any backup that lives only on this Mac.

---

## Status

This is a foundation. The threat model above is measured; the controls are
partly built. The next thing to decide is where a second copy of the
prediction book should live — and that is the owner's call, because every
option trades convenience against a different failure.
