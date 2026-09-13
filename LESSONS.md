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

## L031 — I set a question without checking whether it was already answered
**Found** 2026-09-13, on the first pass through the section I had just written · **status: closed**

Writing the open-questions section, I put the technical gate at the top and
wrote: *"the backtest exists to avoid waiting, and no pass has used it for this
question."*

**It had.** On 2026-09-02 a pass ran five deliberate re-phasings, tabulated the
gate's p-value across all of them, and concluded — correctly — that the effect
was direction-stable and significance-unstable. The result was written into
COWORK.md a thousand lines above where I was typing, and the `--grids` flag I
would have needed already existed, added by that same pass.

So the mechanism I had just fixed — a prompt steering every pass at nothing —
I immediately refilled with a question steering the next pass at settled work.
The failure mode was not the empty section. It was **writing instructions
without reading what was already there**, and an empty section merely made it
visible.

**Check:** none, and that is the finding. There is no mechanical test for "did
the author read the file". What there is: the section now carries a retired
list with the answers and dates, so the next person to ask is answered by the
document rather than by a re-run.

**And the accident was worth more than the answer.** Re-running to verify
turned up that every documented figure came from `--tickers 50` — a slice of a
117-name watchlist. On the full universe the gate's effect halves and
significance falls from 3/5 grids to 1/5, while the headline edge holds
unchanged. A question asked in ignorance found a defect in the answer that the
informed version would never have looked for.

## L030 — Every bot was committing under the owner's email address
**Found** 2026-09-13, within minutes of building the commit-signing check · **status: closed**

Seven places across six workflows did this:

```
git config user.name  "sentinel audit bot"
git config user.email "yonidavidov10@gmail.com"
```

The name said bot. **The address said human.** So every automated commit in
both repositories was already indistinguishable from one forged with
`git commit --author "DarthGenos <yonidavidov10@gmail.com>"` — which is the
precise thing commit signing exists to expose.

It went unnoticed because it looks like tidiness. Setting the owner's address
on a bot reads as "attribute this to the account", and it is the opposite:
it launders an unsigned, unattributable commit into one that appears to be a
person's.

Building the signing check is what surfaced it — the check immediately flagged
an "Audit history" commit, which was correct and for a reason I had not
expected. **A check whose first finding surprises its author is the check
earning its keep.**

**Check:** `_owner_commits_are_signed` exempts by ADDRESS, deliberately, and
the test for that is the one that matters. Exempting by NAME would have hidden
the whole attack: call yourself "audit bot", use the owner's address, and be
waved through. Each bot now has its own `@users.noreply.github.com` address —
reserved by GitHub for exactly this, resolving to no account, and staying
distinct in `git log` rather than all collapsing into "bot".

And the honest limit, recorded so nobody oversells it later: an attacker
holding a workflow token still commits as a bot and is not caught by this.
What stands against that is the workflows being in git and
`_history_is_append_only`. Signing narrows the hole. It does not close one.

## L029 — A prompt pointed at a section that did not exist, for two weeks
**Found** 2026-09-13, explaining to the owner what the improvement pass does · **status: closed**

The improvement prompt says, in these words: *"WHERE THE OPEN QUESTIONS LIVE:
the end of COWORK.md"*. That section did not exist. Every pass was sent to an
empty destination and filled the gap with whatever the audit happened to be
reporting.

The result, counted rather than guessed: over a fortnight, nineteen edits to
COWORK.md, eighteen to tests, five to notify — against **three** to the model
and **one** to the screener. Every pass worked on plumbing. None worked on
whether the system predicts well, which is the only thing it exists to do.

Nothing caught it because **nothing connects a prompt to the file it
references.** A prompt is documentation that steers an autonomous agent, and
documentation that lies to an agent is worse than documentation that lies to a
person — the person notices the heading is missing.

**Check:** `the-passes-open-questions-section-exists` greps COWORK.md for the
heading. Verified by renaming the heading and watching it fail.

The section is written now, with one question at the top and a rule that a
pass which answers it must replace it. Two questions were previously hardcoded
in the prompt, both answered within a day, after which the prompt steered
passes at settled work for a week — the same failure in the other direction.

## L028 — The injection check passed on a workflow written to be vulnerable
**Found** 2026-09-13, in the first hour of the security foundation · **status: closed**

The new check looked for a line beginning `run:`. A workflow step is written
`- run: |` — the dash comes first. The opening line never matched, so no body
line was ever considered inside a block, and the check reported PASS on a
workflow whose only purpose was to be vulnerable.

It passed on both real projects too. Not because they are clean — they are —
but because it was testing nothing at all. **The green tick was the same green
tick either way, and that is the whole problem.**

Third time this exact shape has appeared: the credential-restore regex that
matched `run:` and a git verb on one line ([[L020]]), the grep expectation
whose config keys the handler never read ([[L023]]), and now this. The common
thread is not YAML. It is that **all three were verified only against the state
they wanted to see.**

**Check:** the block is now found by indentation — the `run:` line's indent
opens it, a line at or below that indent closes it — and both a single-line
`run: echo ...` and a multi-line body are covered. Four tests: the attack
caught, the `env:` fix not flagged, `github.run_id` not flagged, and
`head_ref` caught.

The rule this project keeps relearning, stated once more: **A CHECK IS NOT
WRITTEN UNTIL IT HAS BEEN SEEN TO FAIL.** Not reasoned about — seen. Every time
that step was skipped here, the check was broken, and every time it was taken,
the break was found within a minute.

## L027 — Three mistakes of mine in one session, and what now catches each
**Found** 2026-09-13, after the owner asked whether any of this could cause problems · **status: closed**

Not defects in the system — defects in MY editing of it. Worth the same
treatment, because a tool edited by an agent is only as safe as the checks that
watch the agent.

**1. A script deleted a table nobody asked it to delete.** Removing two
expectations from stock-predictor's manifest, it cut from the first match to
the END OF FILE and took `[security]` with it — including the allow-list that
stops the credential scanner flagging documentation which quotes a token shape.

No test caught it, and none could: the tests do not read the manifest. The
audit caught it, in the same run, because a different check flipped PASS to
FAIL. **That was luck, not coverage.**

**Check:** `_manifest_shrank` compares the working manifest against the last
committed one and names every expectation or config key that vanished. A WARN,
not a FAIL — removing a promise the project no longer makes is often right.
What must never happen is removing one WITHOUT NOTICING.

**2. I said a fix protected both projects. It protected one.**
stock-predictor's audit ran the reporter with `|| true`, which swallowed the
new exit code 3 — "ran, found things, reached nobody". The `|| true` had a good
documented reason for exits 1 and 2, and was silently wrong for a case that
did not exist when it was written. Now a case statement: tolerate the audit's
findings, never tolerate its silence.

**3. Twelve .pyc files were tracked in a public repository.** `.gitignore`
listed `__pycache__/` — added AFTER they were committed, and an ignore rule
untracks nothing. Harmless here; the class is not. **The same sequence is how a
`.env` gets published**: committed before the rule exists, then hidden by it,
with `git status` — the one signal that would say so — silenced by the rule
itself.

**Check:** `_ignored_but_tracked`, via `git ls-files -i -c`.

**And a fourth, inside the fix for the first.** The new check parsed the
committed manifest through `run()`, whose default ELIDES THE MIDDLE of long
output. It received a file with 3,185 characters replaced by a notice, failed
to parse it, and reported the manifest as unreadable. The verdict was honest
and the cause was entirely my own call.

Corrupted input that still looks like text is the worst kind: every layer
downstream behaves plausibly and the eventual error names the wrong thing.
`run(clip=False)` now exists for reading rather than showing, with both
behaviours pinned by tests.

Every guard above is tested by REPRODUCING THE MISTAKE in a scratch
repository. A guard verified only against the state it wants has never been
shown to fire, which is the one thing a guard has to do.

## L026 — An undeclared model is an undeclared dependency
**Found** 2026-09-12, auditing where a strong model was being spent needlessly · **status: closed**

The question was where Opus was being used for work that did not need it. The
answer was nowhere: all three cloud workflows — both self-improvement passes
and the market summary — were already running Sonnet 5. Read from the run
logs, not from the configuration, because the configuration said nothing.

THAT SILENCE WAS THE FINDING. Not one workflow declared a model, so each was
getting whatever the account default happened to be that morning. The daily
message a person reads, and the pass that edits two repositories, both
depended on a value written down nowhere. If the default moves, the output
moves with it and no diff records why — the same shape as [[L024]], where a
schedule was documented as a time that never happened.

`--model sonnet` is now explicit in all three. It changes nothing today, which
is the point: it makes today's behaviour the thing that has to be changed on
purpose.

Deliberately NOT raised to Opus, though the improvement passes are the
strongest candidates for it. Raising spend is the owner's decision, not a side
effect of tidying up declarations.

The real waste was outside the workflows entirely: `~/.claude/settings.json`
pinned `"model": "opus"`, which every interactive session inherits AND passes
down to every subagent it spawns. A subagent sweeping files for a pattern does
not need Opus, and nobody chose it there — it was inherited invisibly.
`CLAUDE_CODE_SUBAGENT_MODEL: sonnet` fixes that without touching the
interactive choice, which is deliberate.

**Check:** `_claude_action` in the health checks — every workflow using the
action must declare a model. It reports FAIL naming the workflow, and says
nothing at all for a project that does not use the action, because three
permanent passes about an unused tool is noise.

**And the check moved house.** Two sibling checks for this action lived in
stock-predictor's manifest, written after each mistake was made there. sentinel
runs the same action, in a workflow written later, and was covered by NEITHER —
the project whose job is catching repeated mistakes was repeating them
unguarded. All three now live in the health checks, where every audited project
gets them, and the manifest copies were deleted rather than left to report
everything twice.

**Footnote, and not a small one.** The script that deleted those two
expectations cut to the end of the file and took the whole `[security]` table
with it, including the allow-list that stops the credential scanner flagging
documentation which quotes a token shape. No test noticed — the tests do not
read the manifest. The AUDIT noticed, immediately, because the secrets check
went from PASS to FAIL in the same run. A tool that compares declared
configuration against reality catches a class of regression a test suite
structurally cannot.

## L025 — A new repository inherits nothing, and the second miss hid behind the first
**Found** 2026-09-12, the moment the App grant was fixed · **status: closed**

[[L021]] recorded that a new repository does not inherit the GitHub App grant.
The grant was given. The very next run failed again:

    Environment variable validation failed:
      Either ANTHROPIC_API_KEY, CLAUDE_CODE_OAUTH_TOKEN ... is required

The repository had **no secrets at all**. The token its workflow reads lived in
the other project, and secrets are per-repository exactly like the App grant.
Three days of runs had reported only the 401, because the credential check
comes after the token exchange and never got that far.

So L021 was half a lesson. THE CLASS IS NOT "the App grant" — it is EVERY
PIECE OF PER-REPOSITORY CONFIGURATION A NEW REPO STARTS WITHOUT, and a fix at
one layer reveals the next rather than finishing the job.

**Check:** `_secrets` in the health checks, so every audited project gets it.
It walks the workflows for `secrets.NAME` and asks whether each one exists —
reading configuration instead of waiting for a run, which finds every layer at
once. Inside CI, where listing secrets needs repository admin the Actions token
does not have, it falls back to reading the latest failed run for a
missing-credential complaint, and reports UNKNOWN when neither is available.
"The last run did not fail" is not "the secrets are set".

And the first version of it FAILED AT HIGH SEVERITY ON A HEALTHY PROJECT.
stock-predictor reads two newsletters over IMAP and deliberately works without
them, falling back to the public feed — it says so in its own prompt. Reporting
that as broken every day is the false positive this tool can least afford: a
scanner that cries wolf gets muted, and a muted scanner looks like coverage.
`optional_secrets` in the manifest now declares such a secret, and the check
passes while still printing what is running degraded. A declared choice is not
a defect; hiding it entirely would be the other mistake.

## L024 — Every scheduled run was four hours late, and nothing measured it
**Found** 2026-09-12, checking whether yesterday's fix had held · **status: closed**

`market-news.yml` said `05:00 UTC = 08:00 Israel in summer`. It has never once
run at 05:00. GitHub creates these runs three-and-a-half to five hours after
the cron time — `created_at` equals `run_started_at`, so the lag is in their
scheduler, not in waiting for a runner. The morning market summary arrives
around noon; the daily report, nominally 07:30 Israel, arrives at 11:58.

`daily.yml` even estimated the effect in a comment: "GitHub may delay cron by
15-30 min under load; nothing here is time-critical." Wrong by an order of
magnitude, and that second clause is why nobody looked again for two weeks.

Every check was blind to this BY CONSTRUCTION, and that is the part worth
keeping. The freshness checks ask whether a file was written in the last 96
hours — four hours late passes without a murmur. `schedule_after` compares
cron LINES, so it reasons about times that never occur. The workflows ran,
succeeded, produced fresh output and documented their schedules. Every part
worked. Nothing measured the distance between the promise and the event.

It also explains a failure already written up: the two workflows were given a
thirty-minute gap and now start fourteen minutes apart, both pushing to main.
[[L022]] treated the rejected pushes as a credentials problem. They were also
a collision the clock was supposed to prevent.

**Check:** `schedules-run-close-to-their-cron` measures the real lag per
workflow against a budget calibrated just above today's worst — so it reports
the one thing still actionable, whether the drift GOT WORSE. And
`the-daily-report-arrives-in-the-morning` asks the reader's question instead
of the cron's: did it arrive before 10:00 local?

The budget being calibrated to reality rather than to zero is deliberate. A
check pinned to the cron would fail every morning, say nothing new on any of
them, and teach its reader to skim the line it lives on.

**Decided 2026-09-12:** the late arrival is accepted rather than compensated
for, so the checked promise is the DOCUMENTED hour and not the cron. Chasing a
lag we do not control would mean re-guessing the offset every time GitHub's
load pattern moves. The cron and the comment now move together or not at all —
one changing without the other is exactly how the original claim became
fiction.

And a third check, from the same measurement:
`the-two-pushing-workflows-do-not-collide`. **A CRON GAP IS AN INTENTION, NOT
AN OUTCOME.** daily.yml moved to 03:30 UTC to restore real spacing; the check
takes its verdict from the TIGHTEST day rather than the median, because one
collision loses one message and averaging it against three quiet days is how a
real failure becomes a comfortable number.

## L023 — A key the handler never reads
**Found** 2026-09-11, while writing the check for L022 · **status: closed**

The new expectation was written `path = "..."` / `expect = "absent"`. The grep
handler reads `paths` and `must_match`. Both keys landed in `config` and were
never looked at, so the check ran on its DEFAULTS — search the whole
repository, require at least one match — found one in the manifest's own
explanatory prose, and reported PASS.

Deleting the line it existed to forbid changed nothing. It could not fail.
That is worse than an absent check: it occupies the place a real one would
have taken, and tells whoever reads the summary that the promise holds.

**Check:** the loader now rejects a key its handler does not read, and reports
that expectation UNKNOWN with the nearest real key named.

And the first version of THAT table was typed from memory: it invented
`expect_output` and `forbid_output` and missed `expect_stdout_contains` and
`expect_stdout_absent`, which the command handler genuinely reads — four
working expectations would have been condemned as typos. The same mistake,
pointing the other way. `test_config_keys_matches_what_the_handlers_read`
parses the handlers and fails if the table drifts from them.

## L022 — A warning left the run green, and two messages were lost
**Found** 2026-09-11, chasing one CI failure and finding another · **status: closed**

The market summary of 2026-09-10 was delivered and read. All three pushes were
refused. The step printed `::warning::Could not push the archived message.`,
exited 0, and GitHub marked the run SUCCESS. No alert fired, because as far as
Actions could see nothing had failed. The same thing happened on 09-11, where
an unrelated error happened to turn the run red.

Two mornings the owner read a message the site shows as silence. The archive
held zero market-news rows — not one, ever — while every surrounding check was
green: the workflow existed, it ran, its schedule was documented, the reports
file was fresh. Every PART worked. Nobody asked the whole question.

Three things were wrong, and only the first is about git:

1. The credential restore was missing (see [[L020]]).
2. **The step reported success after failing at its job.** A warning is for
   something that did not matter. Losing a delivered message is not that.
   Archiving is not a nicety attached to sending — it is half the job, and if
   it did not happen the job did not succeed.
3. **What was sent existed in exactly one place, and that place was the
   runner.** There was no way to recover it afterwards, and there still isn't
   for those two days: the text is gone.

**Check:** `nothing-sent-is-missing-from-the-archive` reads the run history,
finds every run whose SEND step succeeded, and fails if any of those days has
no row. It asks about the promise rather than about a part of it — a run that
died before sending is exempt, because its silence is honest.
`a-lost-archive-write-fails-loudly` forbids the pattern that hid this.

A run that cannot push now uploads what it sent as an artifact, and the next
run replays it. The two lost days carry a row saying a message was sent and
its text was not preserved — an archive honest about a hole beats one that
looks complete.

## L021 — A new repository does not inherit the GitHub App
**Found** 2026-09-11, in this repo's first daily pass · **status: closed**

The pass failed with `401 Unauthorized — Claude Code is not installed on this
repository`. The subscription token was valid and irrelevant: the App grant is
PER REPOSITORY, and publishing a new one does not carry it over.

The same failure had been solved once already on stock-predictor, weeks
earlier. The knowledge did not travel, because nothing carried it.

**Check:** `claude-github-app-has-access` reads the last improvement run and
fails if it died on that exact error. The first attempt queried the
installations API instead — which needs the App's own JWT, not a user token,
and returned 401 for a repository where the App plainly works. A check that
reports failure on a healthy state is worse than no check, and only comparing
it against a KNOWN-GOOD repo caught it.

## L020 — The same workflow mistake, three times
**Found** 2026-09-11, in the first scheduled news run · **status: closed**

claude-code-action needs two things that are easy to forget and fail late:
`id-token: write` to mint an OIDC token, and a credential restore afterwards,
because the action revokes its own app token and leaves every later git step
unauthenticated.

Both were solved in improve.yml. Writing market-news.yml I made both again —
so the news message was delivered and then the archive write was thrown away by
"Authentication failed", at the very last step of a run that had worked.

**A mistake that recurs across files is one to check, not to remember.**

**Check:** `_claude_action` in sentinel's health checks walks every workflow
using the action and asks for both — plus a declared model, added 2026-09-12.

These began as expectations in stock-predictor's manifest and MOVED HERE, for
the reason this lesson states: sentinel runs the same action, in a workflow
written later, and was covered by neither. A check that only guards the
project it was born in leaves every other project free to repeat the mistake.
Recurring across projects is this same lesson one level up, and the answer is
the same — the check belongs where every project gets it.

The first version of the credential check PASSED WITH THE STEP REMOVED: its
regex looked for `run:` and a git verb on one line, and shell blocks are
written `run: |` with the commands indented beneath. It matched nothing and
reported success. Only testing the failing case found it — which is the only
way that class of bug is ever found.

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
