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

## L010 — An undocumented schedule
**Found** 2026-09-04, by the owner asking why · **status: open**

`cron: "30 4 * * 2-6"` had no explanation. The reasoning is sound — the run
reports on the previous US trading session, so Sunday and Monday have nothing
to report — but nobody could recover it from the file, and a schedule nobody
understands is a schedule nobody dares change.

**Candidate check:** every `cron:` line in a workflow has a comment within the
few lines above it. Mechanical, cheap, and it would have caught this.
