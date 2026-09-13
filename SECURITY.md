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

## Controls built so far

| Control | Threat | State |
|---|---|---|
| Secrets never committed | intrusion | 4 checks, in place before this |
| No shell injection from event data | intrusion | built 2026-09-13 |
| Actions pinned to a commit | intrusion | measured, reported, **not applied** — see below |
| History is append-only | both | built 2026-09-13 |
| Irreplaceable data has a second copy | our own mistakes | **built, two layers, both verified by restoring** |
| The archive keeps receiving | our own mistakes | built 2026-09-13 |
| Manifest cannot shrink unnoticed | our own mistakes | built 2026-09-13 |
| Nothing tracked that .gitignore claims to hide | both | built 2026-09-13 |

### History is append-only — what replaces branch protection

GitHub refuses branch protection on a private repository on a free plan, and
these repositories hold a record that cannot be recreated while several
unattended workflows carry `contents: write`.

So `sentinel record` writes `.security/history.json` — the commit this
repository was last seen at — and every audit asks one question: **is that
commit still reachable from HEAD?** A normal push only ever adds. A rewrite
orphans what was there, and an intruder covering their tracks and an owner
force-pushing the wrong branch leave identical evidence.

Recording is a SEPARATE command from auditing, deliberately. An auditor that
updates the state it checks against, in the same breath, cannot report a
problem — it would overwrite the evidence while looking at it.

**How strong it actually is.** The ledger lives in the repository it describes,
so whoever can rewrite history can also forge the ledger. That makes it
complete against accident — the case with four days of evidence behind it — and
partial against an attacker, who must know to forge it. Real tamper-evidence
needs a witness outside the repository. Worth building; not what this is.

### The two backup layers, and why there are two

| | Layer 1 — archive repo | Layer 2 — external SSD |
|---|---|---|
| Runs | daily, automatic | monthly, by hand |
| Force-push / bad rebase / corrupted book | ✅ | ✅ |
| GitHub account compromised | ❌ same account | ✅ |
| Credential it needs | deploy key, one repo | **none** |

**The second layer is manual on purpose, and that is the whole design.**
Automating a copy to anywhere off GitHub means storing a credential for the
destination inside the thing being backed up from — which hands an attacker
both at once and defeats the reason for having it. So the one control that
covers an account compromise is the one a person performs, and
`backup-reminder.yml` sends a note on the 15th of each month counting what is
currently at stake.

A deploy key rather than a token for layer 1: a fine-grained PAT still belongs
to the account and must carry an expiry, which is a silent failure a year out.
A deploy key belongs to one repository by construction — whoever steals it can
write snapshots into an archive and nothing else.

Both layers store a SQL dump, not a copy of the `.db`. A database file is
opaque to git: undiffable, unmergeable, and a corrupted byte in the middle
stays invisible until something reads that page.

**And both are verified by RESTORING them**, not by checking they were written.
Confirmed end to end on 2026-09-13: the archive was cloned from GitHub, its
snapshot restored, 142 rows compared. A backup nobody has ever restored is not
a backup — it is an untested belief about a file.

### On "make the code unviewable and unmodifiable by outsiders"

Measured rather than assumed:

* `stock-predictor` — **private**
* `fundamental-engine` — **private**
* `sentinel` — **public, deliberately.** It holds no project-specific anything,
  and being public is what lets every project pull it as a plain checkout.

So "unviewable" is already true where it matters. The perimeter is not the
repository setting — it is the GitHub account, and every control below it is
downstream of that account staying uncompromised. What actually raises the
floor, in order of value:

1. **A second copy of what cannot be recreated**, somewhere a bad push cannot
   reach. Still the top item, still undecided.
2. **Two-factor on the GitHub account**, if it is not already on. Everything
   here rests on it.
3. **Pinning actions to SHAs**, accepting that something must then update them.
4. **Signed commits**, so a forged commit is distinguishable from a real one.
   Currently nothing here would tell the difference.

None of these is blocked by anything except a decision.

## Status

This is a foundation. The threat model above is measured; the controls are
partly built. The next thing to decide is where a second copy of the
prediction book should live — and that is the owner's call, because every
option trades convenience against a different failure.
