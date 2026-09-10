# Lessons — problems found, and the check that would have caught them

Every entry here is a defect that got past everything already in place. The
point of the file is the last column: a fix repairs one instance, a **check**
catches the whole class forever.

**The loop.** When a problem is found — by a person reading, by an audit, by a
daemon — it is written here first with `status: open`. The weekly
self-improvement pass reads this file before doing anything else and its
highest-priority work is turning an open lesson into a check. When one becomes
a check, its status changes to `closed` and names the check.

**An open lesson is not a failure.** Some genuinely cannot be checked
mechanically, and saying so plainly is better than inventing a check that
passes for the wrong reason. Those are marked `unmechanisable` with the reason.

---

## L001 — A check that ran before the thing it was checking
**Found** 2026-09-04, by reading the schedule · **status: closed**

The audit workflow was scheduled at 06:00 UTC "after the daily run". The
self-improvement daemon edits and pushes code at 06:40. So the audit inspected
the repository forty minutes *before* the thing most likely to break it; a
breakage at 06:40 went unreported for twenty-three hours, and the next daily
run used the broken code first.

Both workflows were valid. Both ran. Both were green. Only the **order** was
wrong, and order is invisible unless something looks at it.

**Check:** `schedule_after` — passes on a `workflow_run` trigger, or on a cron
later than every one of the writer's. Catches the subtle case too: 09:00 beats
a 06:40 pass and loses to an 18:40 one.

## L002 — A green pipeline running zero tests
**Found** 2026-09-04, while adding CI · **status: closed**

`unittest discover` died with "Start directory is not importable" because
`tests/` was not a package — and **discover exits 0 when it collects nothing**.
Adding the workflow without noticing would have produced a permanently green
pipeline that ran no tests at all, which is worse than no pipeline because it
actively reports that the code is fine.

**Check:** `health` asserts a collected count against `[commands].min_tests`.

## L003 — A test that wrote to the live database and passed
**Found** 2026-09-04, by a migration counting a row that should not exist ·
**status: closed**

A test reassigned `store.DB_PATH` and expected the write to fail. But
`get_connection`'s default argument was bound at import, so the call reached
the **real** prediction book, inserted a row, and passed. It passed for the
wrong reason, and the row sat in the live archive until the numbers stopped
adding up.

**Check:** `grep` on the guard in `tests/__init__.py`, which makes the live
database read-only for the duration of the suite.

## L004 — A regex that compiled, warned, and matched nothing
**Found** 2026-09-04, from a FutureWarning nobody would have read ·
**status: closed**

An expectation used POSIX classes — `[[:space:]]` — which Python parses as a
nested set and merely *warns* about. The expectation went green while matching
nothing at all.

**Check:** the `grep` kind promotes any regex warning to UNKNOWN.

## L005 — A scanner that invented a match
**Found** 2026-09-04, when a count disagreed with grep's · **status: closed**

Reading a `.pyc` with `errors="ignore"` turns bytecode into a string that
matches almost any pattern. The audit reported three hits where grep found two.
A scanner that invents a match is worse than one that misses, because the false
one gets investigated.

**Check:** `_scannable()` skips caches, virtualenvs and binaries.

## L006 — An expectation that tripped over its own documentation
**Found** 2026-09-04, on the first real manifest · **status: closed**

"Hit rate is never scored against a target" failed on two *comments* explaining
that the target had been retired. An expectation that fights its own docs gets
disabled, and a disabled expectation is a promise nobody is checking.

**Check:** `ignore_comments` on the `grep` kind — and the deeper lesson, now in
the improvement prompt: prefer a pattern that matches **behaviour** over one
that matches prose.

## L007 — A token-shaped string in a test fixture
**Found** 2026-09-04, by this tool auditing itself before publication ·
**status: closed**

A complete token-shaped literal in source poisons every credential scanner that
reads the repo. "It is only a fixture" is exactly what someone says about a
real one too. Excluding `tests/` from the scan would have opened a genuine
hole; assembling the fixture at runtime closed it with no hole at all.

**Check:** the `security` scanner covers every tracked text file, tests
included, with no directory exemption.

## L008 — A run in progress reported as a failure
**Found** 2026-09-04, minutes after publication · **status: closed**

A CI run that has not finished has no conclusion, which `gh --jq` renders as
the string `"null"` — and it fell through to the failure branch. Wrong twice
over: nothing was broken, and the audit is frequently what *triggered* the run
it was judging.

**Check:** `health._ci_status` treats an unfinished run as UNKNOWN.

## L009 — A message that named its subject but not its sender
**Found** 2026-09-04, by the owner reading the first live report ·
**status: closed**

The Telegram message opened with `stock-predictor`, which reads as a message
*from* that project rather than a bug report *about* it.

**Check:** none — this is a wording decision, not a class of defect.
`unmechanisable`, and that is the honest answer.

## L019 — A binary file lost a write to `git pull --rebase`
**Found** 2026-09-10, by checking the archive instead of trusting the green run ·
**status: closed**

The first successful market-news run reported everything green. The message
really was delivered, the runner's own log said "5 archived messages" — and the
JSON that reached the repository held four, none of them the news.

`git pull --rebase --autostash` cannot merge a binary file. Replaying the
commit over a remote that had also touched `predictions.db` resolved to one
side, and the side it picked was the remote's. The write existed on the runner
and did not survive the push.

The daily report never hit this because nothing competes with it for that file
at 04:30. The news job runs at 05:00, alongside everything else.

**What made it visible:** the workflow said success at every step. Only reading
the archive afterwards showed the message was not in it. A green pipeline is
evidence that the steps exited zero, not that the thing happened.

**Check:** the workflow now pushes first and, on rejection, takes the remote
database, replays this run's messages into it from a log written at send time,
and amends. SQLite merges at the row level, which is the only place a merge of
that file can be correct.

## L018 — An alarm about a problem that had already been fixed
**Found** 2026-09-10, in the first message after the fix shipped ·
**status: closed**

`recurring` counted every appearance in the stored history and never asked
whether the finding was still open. So the CI-status bug — fixed two days
earlier — kept being warned about, and would have gone on for another month
until it aged out of the sixty-report window.

An alarm about a problem that no longer exists is precisely the noise this
warning was added to prevent, so it had become the thing it was built to catch.

**Check:** `recurring(still_open=...)` takes the set of findings the CURRENT
audit reports and keeps only those. The raw historical count is still available
for the ledger, which wants the real number.

## L017b — A warning that withheld its own content
**Found** 2026-09-10, same message · **status: closed**

The Telegram formatter attached evidence to FAIL only, so a warning could not
carry a list. Sound as a default — a warning arriving with a code dump is how a
report becomes a wall of text — and wrong for this one: the recurring-finding
warning said "1 finding reported 5+ times" and withheld WHICH, leaving the
reader to go and look. That is the same defect it exists to catch, one level
up: a message that costs work to act on gets skipped.

**Check:** evidence now rides along for FAIL and for HIGH-severity warnings. A
warning that names a list is not a code dump; it is the finding itself.

## L017 — A bug found in one project, living in another
**Found** 2026-09-08, by the owner asking why it did not fix itself ·
**status: closed**

The audit found a real defect and nothing repaired it. Not because a guard
blocked the repair — because of geography. The finding surfaced while auditing
`stock-predictor`, but the bug was in `sentinel`'s own code, and no daemon
crosses that line: the audited project gets the auditor as a throwaway checkout
it cannot push to, and the auditor's own pass ran WEEKLY, so the fix would have
waited six days.

**The auditor is the only thing that can repair a broken check**, which makes
its cadence the slowest link in the whole loop. Weekly was chosen when this was
a small tool nobody depended on; it is now the thing every other project's
health is measured with.

**Check:** the pass is daily now, and `health._never_passed` flags any check
that has run six times and never once passed — the mechanical form of "suspect
the check, not the project". Distinct from `_recurring`, which asks whether
something is still open: a genuine long-standing problem answers that honestly,
while never having passed at all points at the check.

## L016 — A check that judged the run that was asking
**Found** 2026-09-08, by the recurring-finding warning it had just been given ·
**status: closed**

`gh run list --limit 1` returns the most recent run. Inside CI, that IS the
audit currently executing — it has no conclusion yet, so the CI-status check
reported "has not finished" every single time. A question that could never be
answered, asked twice a day.

It appeared in 9 of the first 10 messages and nobody noticed, because one
UNKNOWN line in one report looks like ordinary weather. Only the sequence made
it visible — which is precisely what the recurring-finding check was added for,
and it paid for itself on the first report after it shipped.

It is also invisible from a laptop: run locally, `--limit 1` returns some other
finished run and the check passes. Only the cloud has the failing shape.

**Check:** the command now asks for `--status completed` and skips anything
still in progress, with a test asserting the filter is present — since a test
that merely calls the function passes either way outside CI.

## L015 — Findings were sent and nothing read them back
**Found** 2026-09-05, by the owner asking that messages come back for review ·
**status: closed**

Each report was a fresh look at the code and nothing looked at the reports. So
the most valuable signal the system produces was being thrown away: **a finding
that appears in every message for a week is a failure of the system, not a
finding.** Either nobody is acting on it, or it is not really a problem and the
report has been crying wolf daily. Neither is visible from one report — the
audit that ran an hour ago cannot tell you it is the fourteenth time it said
the same thing.

Both outcomes are real work, and they point opposite ways: still a problem, fix
it; not a problem, stop reporting it. A check nobody acts on is worse than no
check, because it teaches the reader to skim the section where the findings
that matter live.

**Check:** `.audit-history/` keeps the last sixty messages actually SENT — not
audits that ran, since a silent audit told the reader nothing — and
`health._recurring` warns when a FAIL or UNKNOWN has been reported five times
and is still open. WARNs are excluded: a recurring warning is usually a
deliberate "not now".

## L014 — The audit reported, and nothing acted on it
**Found** 2026-09-05, by the owner asking whether it also fixes ·
**status: closed**

The audit ran, found real breakage, and sent it to Telegram. The
self-improvement daemon ran separately and never read any of it. So findings
went to a chat app and stopped there, while a daemon with the ability to fix
them spent its pass guessing at what to work on.

Nothing was broken. Two working systems simply had no wire between them, and a
bot called "Bug Fixer" that only reports is misnamed.

**Check:** none — this is a workflow-wiring decision. `unmechanisable` inside
the repo, though the wiring itself is now verified: improve.yml generates a
fresh report and the prompt makes fixing a ❌ the highest-priority work.

## L013 — A scanner that flagged PyTorch's inference switch
**Found** 2026-09-05, in the first real cloud report · **status: closed**

`\beval\s*\(` matched `model.eval()` and `self.eval()` — PyTorch's
inference-mode switch, which appears in every torch codebase and has nothing
to do with Python's builtin. Two false positives in the first report anyone
actually read. A scanner that cries wolf gets muted, and a muted scanner looks
like coverage.

**Check:** the pattern is now `(?<![.\w])eval\s*\(` — the builtin is never
preceded by a dot.

## L012 — A check that did not apply, reported as unchecked
**Found** 2026-09-05, in the first real cloud report · **status: closed**

"Nothing is scheduled on the owner's Mac" ran in Linux CI, where launchd does
not exist, and reported UNKNOWN. Technically true and practically corrosive:
it put a permanent unactionable line in every report, and a reader who learns
to skim one line skims the section — which is exactly where the real unknowns
live.

UNKNOWN means "this applies here and I could not check it". SKIP means "this
does not apply here", which is a decision rather than an omission. Collapsing
the two costs the report its credibility.

**Check:** the `command` kind now takes `skip_exit` beside `unknown_exit`.

## L011 — A branch protection that locked out the only maintainer
**Found** 2026-09-04, one minute after enabling it · **status: closed**

`main` was protected with `required_status_checks: ["tests"]`. The next push
was rejected: *"Required status check tests is expected."* The check runs **on**
a push, so it can never have passed for a commit that has not been pushed —
and with no pull-request flow on a single-maintainer repo, there was no other
way in. A protection that blocks the person it protects is not protection, it
is a lockout.

Force-push and deletion blocking are the parts that actually matter here: they
stop history being rewritten or lost. Required status checks belong with a
pull-request flow, and adding one without the other is the mistake.

**Check:** none yet — GitHub branch settings are not in the repository, so
nothing in a checkout can see them. `unmechanisable` from inside the repo; it
would need an API call, and that is a real candidate for a future kind.

## L010 — An undocumented schedule
**Found** 2026-09-04, by the owner asking why · **status: closed**

`cron: "30 4 * * 2-6"` had no explanation. The reasoning is sound — the run
reports on the previous US trading session, so Sunday and Monday have nothing
to report — but nobody could recover it from the file, and a schedule nobody
understands is a schedule nobody dares change.

**Check:** the `documented` kind — every line matching a pattern must carry a
comment within the few lines above it. It generalises past cron to any value
whose reason is not recoverable from the code around it: a magic threshold, a
`# type: ignore`, a retry count.

Closing it found a second instance immediately: `audit.yml`'s floor cron had a
long explanation eight lines up, separated from the line it explained. A reader
looking at the line did not see the reason, which is the whole point.
