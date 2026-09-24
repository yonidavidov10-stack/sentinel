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

## L044 — The test guarded another repo from one laptop
**Found** 2026-09-24, when a deliberate change turned CI red · **status: closed**

Two tests asserted that both audit workflows summon an improvement pass — this
repo's and stock-predictor's — by walking to
`../שוק-ההון/stock-predictor/.github/workflows/audit.yml`.

That path exists on the owner's Mac and nowhere else. In CI the file was simply
absent, `continue` fired, the loop body never executed, and the test passed
having examined nothing. It had been "protecting" the other project from a
single machine for as long as it existed.

It surfaced only by accident: removing this repo's own summon took the checked
count to zero, `assert checked` fired, and the suite went red in CI while
staying green locally — the precise split this project has a standing rule
against. Had one workflow still qualified, the hole would have stayed open.

**Check:** none to add — the fix is structural. stock-predictor's gate is now
tested in stock-predictor, beside the file it guards, running on every push
there. What stayed here is what this repo can see about itself. The rule it is
an instance of was already written: THE PLACE A CHECK RUNS IS PART OF THE
CHECK. What is new is the shape — a cross-repository assertion degrades into
silence rather than an error, because a missing file reads as "nothing to
check" instead of "I could not look". That is an UNKNOWN wearing a PASS.

## L043 — A pin nobody bumps is worse than no pin
**Found** 2026-09-24, in the same breath as the pin · **status: closed**

Every audited project checked sentinel out at `main`, unpinned, on every run,
so any commit here — including an agent's — changed the standard they were all
judged by within minutes, unreviewed. Pinning to a SHA fixes that.

And immediately creates the opposite failure. Before, a project was always
audited by the current checks. After, it can be audited by a frozen copy
forever, and every check written since simply never runs there. Both directions
are silent, because a frozen auditor still reports green.

The first pin made the point by itself: it named the commit BEFORE the staleness
check existed, so the guard against a frozen auditor was itself frozen out.

**Check:** `_the_auditor_pin_is_current` — compare each pinned `ref:` against
that repository's HEAD, FAIL past 25 commits. Being behind is the POINT and must
not trip it; a pin untouched for a month is not a decision any more. Two
workflows pinning the same repo to different SHAs also FAIL: that is a split
standard, and the report cannot say which one spoke.

## L042 — Silencing the alarm is not fixing the thing
**Found** 2026-09-22, by the owner saying it only ever reports · **status: closed**

The owner said the bot finds problems and never fixes them, and that the same
findings keep coming back until he pastes them into a session by hand. The
message archive agreed exactly: four findings repeated across 23 consecutive
reports over nine days.

Nothing was wrong with the audit. The pass that acts on what it finds had
failed on all eleven of its runs — its token secret was refused in 82ms — and
that morning I DISABLED IT, wrote it up as a deliberate decision, and taught
`_no_workflow_always_fails` to skip disabled workflows so the warning would
clear. It cleared. The reports carried on twice a day into a loop whose other
half no longer existed.

Every step was defensible on its own. Together they converted a loud, correct
FAIL into silence, and I reported the silence as progress. The check I wrote
that morning was the thing that blinded the system.

A disabled workflow IS a decision — for one job. The fixer is not one job: it
is the half of the loop that acts, so turning it off strands every finding the
audit will ever produce. The same fact means opposite things depending on which
workflow it is about, and the general check could not tell.

**Check:** `_the_fixer_can_act` — find the pass this project's audit summons by
reading `gh workflow run` out of the workflows (never assume `improve.yml`; a
renamed pass would pass a hardcoded check while fixing nothing), then FAIL if
it is missing, disabled, or failing every run. `needs_owner`, because only a
person can re-enable a workflow or replace a secret — and summoning the daemon
to repair the daemon is a loop. `_no_workflow_always_fails` now leaves this one
workflow to it, so exactly one check speaks about it.

Also: the summon step logged "the scheduled pass will pick it up" when dispatch
failed. A disabled workflow refuses dispatch and has no schedule. The fallback
was false in precisely the case that produced it.

## L041 — I fixed the branch that is never taken
**Found** 2026-09-22, five days after "fixing" it · **status: closed**

The bot's report, verbatim:

> כל סוד שהתהליכים מבקשים קיים בריפו הזה — 13 הרצות, אפס מעברים

L037 moved the secrets check from UNKNOWN to SKIP because a workflow token
cannot list secrets. The branch it moved was `r.ok and not r.stdout.strip()` —
an EMPTY list. Inside Actions `gh secret list` is not empty, it is **refused
with 403**, so `r.ok` is false and control goes somewhere else entirely.

**The branch I fixed is never taken where it matters.** Thirteen runs, zero
passes, still the top line of `_never_passed` five days later — the warning
telling me, every morning, that the fix had not landed.

Testing only the state you want has an outer form: **fixing only the branch you
were looking at.** I had the failing case in front of me — a 403 in the
evidence of the very finding I was reading — and edited the other one.

**Check:** the test for this branch now pins SKIP, and pins that it is still
not a PASS.

## And a warning that accused a check of doing its job

> אף תהליך לא נכשל בכל ריצה — 9 הרצות, אפס מעברים

`_no_workflow_always_fails` was correctly reporting that sentinel's improvement
pass had never once succeeded. `_never_passed` listed it as a suspect anyway,
because it counted a FAIL as "not a pass".

**A FAIL is an ANSWER.** This warning exists to find checks that can never
answer — the ones stuck on UNKNOWN because their environment cannot tell them.
A check returning FAIL is reporting a real problem nobody has fixed, which is
`recurring`'s job.

So one real problem arrived as three findings: the FAIL itself, a "suspect this
check", and a "this keeps recurring". **A report that says the same thing three
ways is how a reader learns to skim all three.** `_never_passed` now ignores any
check that has ever answered FAIL.

## L040 — The self-improvement pass never ran once, and nothing said so
**Found** 2026-09-17, clearing the last findings · **status: closed**

sentinel's `improve.yml` has failed on every run since 2026-09-13:

```
CLAUDE_CODE_OAUTH_TOKEN ... is required
```

The secret exists and holds an empty string — the second of the owner's two
attempts to set it, both on 2026-09-13. A validating script was written for the
third attempt, the conversation moved to the bot secrets, and **I never went
back to confirm the Claude token had been fixed.** The timestamp still reads
04:14:20.

**So the tool meant to improve itself has never improved itself.** And no audit
said so. Every one reported the project healthy, because:

* `_ci_status` judges the latest run of ANY workflow, and that was always a
  green `tests` or `audit` run;
* `_secrets` checks that a secret NAME exists — it cannot read the value, and
  an empty value is present.

That is the premise of this whole tool, missed by this tool: something that is
supposed to happen, not happening, every day, with nothing saying so.

**Check:** `_no_workflow_always_fails` judges each workflow on its own last four
real verdicts. It went red on sentinel immediately.

## The same day, three more of the same family

**The collision check failed on data its fix had replaced.** daily.yml moved on
2026-09-12; every day since came in 51-57 minutes apart; the check took the
tightest day of the whole window, a 14-minute day from the old schedule. Now it
judges only days since the last commit that changed a `- cron:` line, read from
git. Third instance of judging the current configuration by evidence from the
previous one, after `recurring` and `never_passed`.

**The allowed_bots check was a false positive.** It flagged every workflow with
a `workflow_dispatch` trigger. market-news.yml was reported though nothing has
ever dispatched it, and the only "fix" was to widen what a bot may trigger for
no reason. It now flags only targets of a real `gh workflow run` in another
workflow.

**A test passed on the laptop and failed in CI, an hour after L039 said exactly
that.** The backup check had just learned to answer SKIP when
`GITHUB_ACTIONS=true`, and the older test did not clear it. The conftest now
clears the CI variables too, and the suite is run both ways before committing.

## L039 — A lesson applied to one check and not its siblings
**Found** 2026-09-17, from the bot, two days after the lesson was written · **status: closed**

The daily report listed three checks that had never passed:

```
backup second copy      10 runs, 0 passes
commits signed           9 runs, 0 passes
secrets exist            8 runs, 0 passes
```

L037 had fixed the third two days earlier — a question a CI runner structurally
cannot answer is SKIP, not UNKNOWN — and **the other two were the same lesson,
not applied.** The owner had said it in the message before: a conclusion reached
on one side belongs on both. I wrote it down and then did it for one check.

**The backup check** asked a CI runner whether `/Volumes/T9 Davidov/...`
existed. It can never exist there. SKIP in CI now; still UNKNOWN on the owner's
machine, where an unplugged drive genuinely might have been checked.

**The signing check was worse, because it did not know it was blind.** `%G?`
VERIFIES, and verification depends on the machine. With the owner's
`gpg.format=ssh` and `allowedSignersFile`, a signed commit reads `G`. In CI,
with neither, git prints *"allowedSignersFile needs to be configured"* and
reports the same commit as `N`. So it counted every signed commit as unsigned
wherever it actually ran — **21 of 30 in CI against 1 of 30 on the laptop**, a
number that could never fall. It now reads the raw `gpgsig` header: presence
was always the question, and presence is identical everywhere.

**And the check that caught all this had its own hole.** `_never_passed` skipped
SKIP rows but kept the OLD UNKNOWN rows of a check since reclassified, so a
fixed check went on being reported for sixty messages. A check whose latest
verdict is SKIP is now excluded outright.

**Then eighteen tests broke that had not changed.** `commit.gpgsign` is on
globally, the key has a passphrase, and after a restart the agent was empty —
so every scratch-repo commit in the suite failed. **The suite was reading the
developer's machine.** CI, with no such config, would never have seen it. A
conftest now gives every test an empty git config, and the suite passes with
the agent emptied on purpose.

And the same restart meant **every real `git commit` on the owner's machine was
failing** — the "type the passphrase once" I promised does not survive a
reboot. `~/.zshrc` now loads the key from the Keychain on every shell.

**Check:** `test_a_signed_commit_counts_as_signed_with_no_git_config_at_all`,
`test_a_local_path_in_ci_is_skip_not_unknown`,
`test_a_check_reclassified_to_skip_stops_counting_as_never_passed`, and the
conftest itself.

**The rule, stated so it cannot be half-applied again:** when a lesson is about
an ENVIRONMENT — CI cannot see X, a clean git cannot verify Y — search every
check for the same dependency before closing it. The lesson is about the
environment, not about the check that happened to reveal it.

## L038 — The summoned pass refused to run, for weeks
**Found** 2026-09-15, from the owner saying it a third time · **status: closed**

> "מתכן הבאגים עדיין רק שולח הודעה ולא מסדר"

Said twice before and answered twice with wiring that was correct. The wiring
WAS correct. The audit fired, decided, dispatched — and the pass died on its
first step:

```
Action failed with error: Workflow initiated by non-human actor:
github-actions (type: Bot). Add bot to allowed_bots list.
```

`claude-code-action` blocks non-human actors by default. That is a good guard —
a compromised automation triggering an agent with write access is exactly the
attack it prevents — and it is precisely what this system is built to do on
purpose. `gh workflow run` from the audit runs as `github-actions[bot]`, so
**every summoned pass has died before starting since the loop was built.**

**IT HID BEHIND THE HALF THAT WORKED.** Scheduled passes ran fine and did real
work, so `improve.yml` showed a healthy mix of successes. Only the dispatched
runs failed, and only they were the ones the audit had asked for. From outside
it looked exactly like a system that reports and never fixes — which is what
the owner said three times, correctly, while I twice fixed the wrong layer.

**What I should have done the first time: follow the summoned run.** I verified
the decision, the gate and the dispatch, and never once opened the run that
dispatch produced. The question "does it summon" is not the question "does the
summoned thing work".

**Check:** `_claude_action` now reports any dispatchable workflow using the
action without `allowed_bots`.

And the check's first version passed with the setting deleted — it searched for
the bare word, which appears in the comment ABOVE the setting explaining why it
is there. **Third time a check has tripped over its own documentation.** A grep
for a config key anchors to the key.

Its second version appended a finding only on failure, so a clean project
produced no line at all — indistinguishable from a check that is not running.
Silence is not evidence, and that is the fourth time this file has said so.

## L037 — SKIP is the answer when a check cannot apply where it runs
**Found** 2026-09-15, from the bot's own report · **status: closed**

The daily message carried this, unprompted:

> 2 בדיקות מעולם לא עברו — החשד הוא על הבדיקה, לא על הפרויקט
> · כל סוד שהתהליכים מבקשים — 6 הרצות, אפס מעברים
> · שני התהליכים שדוחפים ל-main — 8 הרצות, אפס מעברים

`_never_passed` was right about both, and both were mine, written three days
earlier.

**The secrets check needs repository admin, and a workflow token structurally
cannot have it.** Reported as UNKNOWN it was permanently unanswerable — an
unactionable line in every single report, which teaches its reader to skim the
section the real unknowns live in. That is not vigilance, it is decay.

SKIP is the honest verdict: *this does not apply here.* A decision, not an
omission. It still checks properly from a laptop whose `gh` is the owner's,
which is where the answer exists. **What must never change is that it is not a
PASS** — silence still never reads as verified.

**The archive check asked GitHub about a PRIVATE repository using a token
scoped to a different one.** "Not Found", every run. Fixed by moving the fact
into the repository that needs it: `daily.yml` writes a marker AFTER the push
succeeds. A marker written before would record an intention.

**The third was not broken, only young** — two overlapping days where three are
needed. "Not enough data yet" and "cannot be checked here" both exit 3, and a
reader who cannot tell them apart eventually treats every UNKNOWN as noise. The
message now says which.

**And a false alarm that fooled me.** `check_archive_gap` reported a day
missing; the row was in `origin/main` and this clone had not fetched. From a
stale checkout the message is indistinguishable from a real loss. It now
refuses to judge while behind the remote — in CI the checkout is always fresh,
so this guard exists purely for the laptop, where being behind is normal and
invisible.

**Check:** `_never_passed` — which already existed and did the whole job here.
It flagged both, by name, with their run counts, in a message nobody had to go
looking for. Nothing new was needed to catch this class; what was needed was
reading what it said instead of assuming the checks were fine because they were
recent.

`test_a_green_latest_run_is_skip_not_a_pass` pins the new verdict and, more
importantly, pins that it is still not a PASS — the failure mode a SKIP could
introduce is silence reading as verification.

**What this session is really evidence of:** the bot caught three defects in
its own auditor and one in its author, and it did so by reporting that its
checks never pass. A tool that measures its own checks is the only kind that
can tell you the measurement is broken.

## L036 — The error path had never run, and it was broken
**Found** 2026-09-13, by a test that was about something else · **status: closed**

`security.check()` builds an UNKNOWN when `git ls-files` fails, and returns it
with `duration_s=t.seconds` — from inside the `with timer() as t` block. The
timer sets `.seconds` in `__exit__`. Reading it early raises AttributeError.

So auditing anything that is not a git repository **crashed the entire security
check** instead of reporting the finding it had just constructed, two lines
above.

It survived because every project ever audited was a git repo. The branch was
written, reviewed, committed and never once executed — and it was wrong the
whole time. **An unexercised error path is not a safety net; it is a second
failure waiting for the first one.**

Found by a test that used a bare temp directory for an unrelated reason. Not by
review, and not by any of the audits this tool has run on itself.

**Check:** `test_the_security_check_survives_a_directory_that_is_not_a_repository`
audits a bare directory and asserts it reports rather than raises. The other
three `duration_s=t.seconds` sites were checked by indentation and are outside
their blocks, which is correct.

**The shape to hunt for:** a `return` inside a `with` that reads something the
context manager sets on exit. More broadly — every branch that only runs when
something has already gone wrong is a branch nothing has tried.

## L035 — The daemon was summoned on one verdict out of three
**Found** 2026-09-13, from the owner: "it still only sends messages and does not fix the problems" · **status: closed**

They were right, and the cause was one line in the audit workflow:

```
if: github.event_name == 'schedule' && steps.audit.outputs.code == '1'
```

Exit 1 means a promise is BROKEN. Every UNKNOWN and every WARN exits 2 and woke
nobody. So the wiring built weeks ago to make this system fix rather than file
was reaching one verdict out of three, and the message the owner pasted —
two UNKNOWN and one WARN — summoned nothing at all.

**An exit code could not express the question.** "Is anything broken" and "is
there anything a pass could act on" are different, and the second is the one
the gate needed.

**Check:** `--should-fix` prints nothing and answers in its exit code. A FAIL
acts now; an UNKNOWN acts once it has RECURRED and is still open — one "could
not check" is information, five means nobody has made it checkable, which is
squarely daemon work. A WARN never qualifies, and that is `history.recurring`'s
existing judgement rather than a new one: it counts FAIL and UNKNOWN only,
because a recurring warning is usually a deliberate "not now".

**And the rule that keeps this from being worse than the bug:** `needs_owner`
findings never summon anything. Rotating a credential, plugging in a drive,
editing a workflow the pass is forbidden to touch — a pass woken for those
looks, finds nothing it may change, and burns a run. Waking a daemon for work
it cannot do is how a fixing loop becomes an expensive reporting loop.

The report now says which is which, because the reader's real question is not
"how bad is this" but "is anything going to happen, or is it waiting for me?"
Until today every finding read the same, and several sat for days because they
looked like the rest.

## L034 — A lock is resolved for one machine, and five CI runs said so
**Found** 2026-09-13, hash-locking the dependency tree · **status: closed**

`requirements.lock` took five CI runs to install once. Four distinct failures,
none of them reproducible locally, and the local environment is precisely why:
the lock was generated on the machine that could not see any of them.

| run | failure | what it meant |
|---|---|---|
| 1 | `audioop-lts` has no 3.12 build | resolved for ONE INTERPRETER |
| 2 | `PyObjC requires macOS to build` | and ONE OPERATING SYSTEM |
| 3 | `setuptools>=77.0.3` unpinned | a hand-added package hides its own tree |
| 4 | `sympy>=1.13.3` unpinned | same shape — fix the class, not the instance |
| 5 | — | passed |

**Runs 3 and 4 are the ones worth keeping.** torch is excluded from the compile
because pip-compile resolves it to the PyPI wheel and 2.5GB of CUDA the project
cannot use. Excluding it hid its whole dependency tree as well, and
`--require-hashes` rejects the entire file over any single unpinned
requirement. Adding them one at a time would have cost one CI run per
dependency and taught nothing after the first. All seven went in at once, read
from `importlib.metadata.requires("torch")` rather than transcribed.

**What pip did right, and it is the point of the exercise:** it refused
everything over one loose requirement. A partial lock is not a weaker lock, it
is no lock, and pip says so instead of installing most of it.

**Check:** the dependency check now tells three states apart — pinned with no
lock (PASS, a real improvement), locked and enforced (PASS), locked and
enforced by nothing (WARN). That last is the same shape as [[L032]]: an
artefact that exists, looks right, and protects nothing.

**The rule this session keeps rediscovering, now with five data points:** THE
PLACE A CHECK RUNS IS PART OF THE CHECK. `gh run list --limit 1` returned the
run asking the question. A regex in POSIX meant something else than in Python.
A lock built on macOS/3.14 described a machine that does not exist in CI. Every
one passed locally.

## L033 — Two scanners claiming the same patterns, in different dialects
**Found** 2026-09-13, on the first run of the history scanner · **status: closed**

The working-tree scanner reads files with Python's `re`. The new history
scanner passed the same pattern strings to `git log -G`, which uses POSIX
regex — where `\b` is not a word boundary and `{8,10}` is not a repetition
count unless the engine is in extended mode.

So the Telegram-token pattern matched correctly in one scanner and **matched
nothing at all** in the other, while a comment above it claimed they used "the
same shapes, so a pattern added there is searched here too". The claim was
sincere and the behaviour was the opposite.

Caught by a test that committed a fake Telegram token and expected a FAIL.
Without it the check would have shipped reporting clean on the one credential
type this project actually uses.

**Check:** the history scan now reads diffs with `git log -p --unified=0` and
applies the SAME COMPILED PATTERN OBJECTS as the tree scanner. Not the same
strings — the same objects. Sharing a string across two regex engines is
sharing a spelling, not a meaning.

**The shape to look for:** any time the same rule is expressed twice in
different languages — a regex in Python and in shell, a threshold in code and
in YAML, a date format in two places — the two will agree in testing and
diverge in production. Share the evaluated thing, not the text of it.

And the first real run found a token in this repository's own history: a
fixture for testing `scrub()`, committed then removed once the tree scanner
flagged it, and therefore permanent. **Deleting a secret from a file does not
delete it.** Allowed by its own placeholder prefix rather than by silencing the
Telegram pattern — silencing a shape to quiet one instance is how a scanner
stops scanning.

## L032 — A control nothing calls is a control that does not exist
**Found** 2026-09-13, hours after building it · **status: closed**

`_history_is_append_only` compares HEAD against a commit recorded in
`.security/history.json`, and `sentinel record` writes that file. The check
shipped. The recorder shipped. **Nothing ever called the recorder.**

The ledger sat nine commits behind in one repo and thirteen in the other, and
the check kept reporting PASS — correctly, which is what makes this worth
writing down. The recorded commit really was still an ancestor.

**That is precisely the failure.** Force-push away the last five commits and a
marker from thirty commits back is still an ancestor. So the control covered an
intruder rewriting an entire branch, and did NOT cover the accident that
actually happens to people: a bad rebase of recent work. It had narrowed,
silently, to guarding the case that never occurs.

A green tick from a control nobody advances is the most expensive kind of
false comfort, because everything about it looks right — the check runs, the
file exists, the verdict is honest about what it compared.

**Check:** both audit workflows now run `sentinel record` after the audit (never
before: a tool that updates the state it checks against overwrites the evidence
while looking at it), and commit the result.
`test_the_audit_workflows_advance_the_ledger` reads the workflow files and
fails if either stops calling it or stops committing what it writes. Two more
tests pin the behaviour itself — a stale ledger missing a recent rewrite, and
a current one catching the same rewrite.

**The shape to look for elsewhere:** every piece of state a check compares
against needs an owner that advances it. Ask, of any stored baseline, *what
moves this, and when*. If the answer is "someone will remember", it is already
stale.

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
