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
| Third-party actions | Were pinned to mutable tags. **Fixed** — 28 references pinned to commit SHAs across three projects. |
| Python dependencies | Were floors (`>=`), so CI installed whatever had been published that morning. **Fixed** — pinned to the versions the suite passes against. |
| Credentials in git history | Was **never checked** — the scanner read the working tree only. Now scanned. |

### The exposure that mattered most, and it was not the tags

**A package's install hooks run as the job installing it.** `pip install -r
requirements.txt` in CI executes inside a job holding the prediction book, the
bot tokens, the archive deploy key and a Claude Code token — and until
2026-09-13 that file said `yfinance>=1.6.0`, `torch>=2.13.0`,
`transformers>=5.15.0`. A floor is not a version; it is an instruction to take
whatever was published most recently, re-evaluated on every run.

**This is the only risk in this document that needs no mistake on our part and
no access to the account.** An upstream compromise anywhere in the transitive
tree is sufficient. Everything else here requires someone to get in, or us to
slip.

Pinned now, to the versions the suite actually passes against — read from the
working environment rather than chosen — with dependabot watching the `pip`
ecosystem so pinning does not freeze the vulnerabilities alongside the
versions. NOT hash-pinned: `--require-hashes` would also defeat a compromised
index serving a different artifact under a known version, and it needs a full
transitive lock regenerated per platform (this builds on macOS arm64 and runs
on linux x86_64). Worth doing, a much bigger change, and recorded here rather
than silently skipped.

### Tags are not versions either

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

### Deleting a secret from a file does not delete it

The credential scanner read the working tree. A token committed in June and
deleted in July is absent from every file it examines and present in every
clone of the repository, forever — and the scanner reports clean the whole
time. **That is the single most common way credentials leak from repositories**
and it went unchecked here until 2026-09-13.

The history scan reads the diffs of recent commits and applies the same
compiled patterns as the tree scanner. The first version passed them to
`git log -G` instead, which uses POSIX regex — a different dialect, in which
`\b` and `{8,10}` mean other things. The Telegram-token pattern matched
nothing there while matching correctly in the tree scanner: two scanners
claiming the same shapes and quietly disagreeing about what a shape IS.

Its first real run found a token in this repository's own history — a fixture
for testing `scrub()`, committed and removed once the tree scanner flagged it,
and therefore permanent. Allowed by its own placeholder prefix rather than by
silencing the Telegram pattern, because silencing a shape to quiet one
instance is how a scanner stops scanning.

**The remedy is rotation, not rewriting.** Every clone taken since already has
it. Treat anything that reached a commit as public.

## What this does NOT protect against

Stated plainly, because a security document that only lists strengths is
marketing.

* **A compromised Mac.** Every credential here is reachable from this laptop.
  The signing key now carries a passphrase held in the macOS Keychain, which
  stops the KEY FILE being copied and used elsewhere — the realistic theft. It
  does NOT stop a process running as this user from asking the agent to sign,
  because the Keychain is unlocked whenever the user is logged in. Worth doing;
  not the same as protecting against a compromised machine, and saying
  otherwise would be the more comfortable error.
* **A compromised GitHub account.** 2FA is on, which is the control that
  matters. If it falls anyway, the external drive is the only thing that
  survives — the archive repo lives under the same account.
* **A stolen workflow token.** Commits made with it are attributed to a bot,
  and bot commits are exempt from the signing check because runners hold no
  key. Signing narrows that hole; it does not close it. What stands against it
  is the workflows being in git and the append-only history check.
* **The improvement pass making the predictions worse.** Its five guards prove
  it did not lie about its work. They say nothing about whether it was right.
* **A dependency compromised BEFORE the lock was generated.** The hashes pin
  what was there on 2026-09-13; they prove nothing about whether it was already
  malicious. Locking freezes a state, it does not vet one.
* **Anything installed outside the lock.** `requirements-voice.txt` is not
  hash-locked, and neither is anything a developer adds by hand on the Mac.
* **Disk loss**, for any backup that lives only on this Mac.

---

## Controls built so far

| Control | Threat | State |
|---|---|---|
| Secrets never committed | intrusion | 4 checks, in place before this |
| No shell injection from event data | intrusion | built 2026-09-13 |
| History is append-only | both | built 2026-09-13; **the ledger now advances after every audit** |
| Commits attributed to the owner are signed | intrusion | built 2026-09-13 |
| Actions pinned + dependabot watching | intrusion | **applied 2026-09-13**, 28 references across three projects |
| Irreplaceable data has a second copy | our own mistakes | **built, two layers, both verified by restoring** |
| The archive keeps receiving | our own mistakes | built 2026-09-13 |
| Manifest cannot shrink unnoticed | our own mistakes | built 2026-09-13 |
| Nothing tracked that .gitignore claims to hide | both | built 2026-09-13 |
| Dependencies pinned + dependabot watching | intrusion | **built 2026-09-13** |
| No credential in git history, not just the tree | intrusion | **built 2026-09-13** |
| Every workflow declares its permissions | intrusion | **built 2026-09-13** |
| Repository visibility matches the declaration | intrusion | **built 2026-09-13** |

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

**A stale ledger only guards ancient history, and that nearly shipped.**
`sentinel record` was written as a separate command and nothing called it —
found hours later, nine commits behind in one repo and thirteen in the other.
The check kept passing, correctly: the recorded commit was still an ancestor.
Which is exactly the failure. Force-push away the last five commits and a
marker from thirty back is still an ancestor, so the control covered an
intruder rewriting a whole branch and did not cover the accident that actually
happens — a bad rebase of recent work. Both audit workflows now advance it,
after the audit rather than before, and two tests pin the difference.

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

## Status, 2026-09-13

**Every item this document opened with is built, and each one is measured
rather than asserted.** Eleven checks run against every audited project, on
every audit, and report to @Bugfixer_BS7bot.

What changed today, in the order it mattered:

1. **Dependencies pinned.** The only risk here that needs no mistake on our
   part.
2. **A second copy of the prediction book**, two layers, both verified *by
   restoring* — the archive cloned from GitHub and replayed, 142 rows
   compared; the drive restored from the drive itself, 138 rows.
3. **Git history scanned for credentials**, not just the working tree.
4. **Actions pinned to SHAs** with dependabot watching, across three projects.
5. **Commits signed**, and every bot stopped committing under the owner's
   address — which had made automated commits indistinguishable from forged
   human ones.
6. **The append-only history ledger wired up**, after it was found guarding
   only ancient history because nothing advanced it.

**The honest caveat about all of it.** Six of these were built today, and four
of the six had a defect found within hours of being written — a check that
passed on a workflow written to be vulnerable, a regex dialect mismatch that
made a scanner silently blind, a ledger nothing advanced, a test that failed on
`sys.path.insert`. Every one was caught by writing the failing case. **Assume
the same rate applies to what has not been examined yet.**

### What to do next, in order

1. **Hash-pin the dependency tree.** `pip-compile --generate-hashes`, per
   platform. The largest remaining gap and the only one with a known answer.
2. **A passphrase on the signing key**, or accept that anyone with the Mac can
   sign as the owner. One command: `ssh-keygen -p -f ~/.ssh/id_ed25519_signing`.
3. ~~Check workflow permissions mechanically.~~ **DONE**, and reading them by
   eye had missed something: three workflows declared no `permissions:` block
   at all — two `tests.yml` and a `smoke.yml` — so they inherited a
   repository-wide default that nothing in the source records, often read AND
   write across every scope. A job that only runs tests may have held the right
   to rewrite the code it was testing. All three now declare `contents: read`.
   `write-all` and `pull_request_target` are checked too; neither appears here.
4. ~~Check repository visibility against a declaration.~~ **DONE.** Visibility
   is not in the source, so the project declares its intent and the audit asks
   GitHub. Declared private and actually public is CRITICAL; the reverse is a
   warning — one exposes everything, the other inconveniences a collaborator.

### Now the next four

1. ~~Hash-pin the dependency tree.~~ **DONE 2026-09-13**, and it took five CI
   runs to install once — four distinct failures, none reproducible locally,
   because the lock was generated on the machine that could not see them. A
   lock is resolved for one interpreter, one operating system, and one set of
   packages the resolver was actually shown. See L034.

   57 packages, 1,169 hashes, `--require-hashes` in every workflow. torch stays
   hand-added from PyTorch's CPU index with its seven dependencies listed
   explicitly so the resolver can see them.
2. ~~A passphrase on the signing key.~~ **DONE 2026-09-13**, with
   `~/.ssh/config` set to `UseKeychain yes` / `AddKeysToAgent yes` so it is
   typed once on this machine. Verified: the key refuses an empty passphrase,
   it is loaded in the agent, and a commit still signs and verifies (`G`).
3. **Secret age.** Nothing knows how long a token has been in place. A
   credential that has not rotated in a year is not a finding today and will
   be one eventually.
4. **The Mac itself.** Every control here assumes the laptop is not
   compromised, and nothing checks that assumption — FileVault, screen lock,
   what else can read `~/.ssh`. It is the largest unexamined surface left, and
   the one this tool is least suited to examine.

**Thirteen checks now run against every audited project.** The caveat above
stands: eight of them were built in a single day, and a defect was found in
half of those within hours of writing them.
