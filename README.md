# sentinel

A project auditor. Each project writes down **what it promises to do**, in its
own words, and sentinel checks whether those promises still hold.

```sh
python3 -m sentinel.cli init .        # write a starter SENTINEL.toml
python3 -m sentinel.cli run .         # audit it
python3 -m sentinel.cli run --all ~/Projects
```

## Why a manifest, and not inference

A test suite verifies the **parts**. It cannot verify the **promise**, because
the promise usually lives outside the process: a report reaching a chat app, a
scheduled job actually firing, a file still being written to.

One of the audited projects had a green suite for the three days its daily
Telegram report silently stopped going out. Every part worked. The thing the
project was *for* did not happen, and nothing said so — a job that never fires
produces no error to notice.

Nothing in that repository's source said "a report must reach its owner every
trading day". So projects say it here instead, and it becomes checkable:

```toml
[[expectations]]
id = "daily-run-produces-output"
says = "The daily pipeline actually ran recently and wrote its results"
why  = "This is the promise that broke on 2026-08-29 and stayed broken for three days."
kind = "freshness"
severity = "critical"
path = "data/public_snapshot.json"
field = "generated_at"        # the file's OWN timestamp; git checkout resets mtimes
max_age_hours = 96
```

The manifest is documentation that fails when it stops being true.

## The one rule everything rests on

**A check that could not run reports `UNKNOWN`, never a pass.**

An auditor that folds "I could not reach it" into "fine" is worse than no
auditor, because its whole value is that someone reads it instead of looking
themselves. Unknowns get their own count in the headline, their own section in
the report, and their own exit code:

| exit | meaning |
|---|---|
| `0` | clean |
| `1` | something is broken |
| `2` | nothing is broken, but something could not be checked |

A scheduler can then treat "it is broken" differently from "I could not look".

## Expectation kinds

| kind | checks |
|---|---|
| `command` | a command's exit code and output. `unknown_exit` marks a code meaning *cannot be checked here* |
| `freshness` | a file was updated recently — by its own embedded timestamp, or its mtime |
| `file_exists` / `file_absent` | a path is or is not there |
| `schedule_after` | a workflow that CHECKS runs after the workflow that CHANGES |
| `grep` | a pattern does or does not appear. `ignore_comments` keeps an expectation from tripping over its own documentation |

An expectation with an **unknown kind is kept, not dropped** — reported
`UNKNOWN` — because a typo that silently removes a promise from the audit while
the report stays green is the same trap as a CI step that collects zero tests
and exits `0`.

### Where new kinds come from

Every kind here started as a defect that nothing would have caught.
`schedule_after` exists because an audit workflow was scheduled at 06:00 "after
the daily run", while the self-improvement daemon edited and pushed code at
06:40 — so the check ran forty minutes *before* the thing most likely to break
it, and a breakage went unreported for twenty-three hours. Both workflows were
valid. Both ran. Both were green. Only the **order** was wrong, and order is
invisible unless something looks at it.

That is the intended loop: when a problem is found by reading rather than by
running, the fix is not only to correct it but to add the check that would have
found it. A kind that catches one class of mistake forever is worth more than a
one-off repair.

## Reporting in another language

An expectation may carry `says_he` beside `says`, and `remedy_he` beside
`remedy`; findings from the built-in checks carry Hebrew too. The Telegram
reporter prefers it and **falls back to English rather than to blank** — a
missing translation must degrade to a readable line, never an empty one.

Explicit fields, not a lookup keyed on the English title: a translation table
matched by string breaks the moment someone rewords a title, and the report
reverts to English with nothing to say why.

## The other checks

**security** — credentials committed to tracked files, `.env` under version
control, `.gitignore` gaps, and a short list of high-consequence code patterns.
Deliberately narrow: a scanner that cries wolf gets muted, and a muted scanner
looks like coverage. Findings name the file and the *kind* of secret, never the
value.

**health** — the suite runs and passes, it is actually collecting its tests, CI
runs it, work is committed and pushed, and a few improvement prompts.

## Reporting

```sh
export BUGFIXER_BOT_TOKEN=...      # never on the command line: shell history, CI logs
export BUGFIXER_CHAT_IDS=123,456
python3 -m sentinel.cli run . --telegram
```

Silent when there is nothing actionable. `--heartbeat` sends an all-clear
anyway — meant for one day a week, so that a **gap** in the reporting is itself
visible. A bot that only ever speaks about problems cannot be told apart from a
bot that has stopped running.

Evidence is scrubbed of credential-shaped strings before sending: a `command`
expectation's stdout is arbitrary, and a report that repeats a secret leaks it
again into a chat log.

## Trust boundary

Commands come from the audited project's own `SENTINEL.toml` and run with this
process's privileges. That is the point — a project must be able to say how to
verify itself — but a manifest is exactly as trusted as the repository
containing it. **Never run sentinel against a repo you would not run `make`
in.**

## Requirements

Python 3.11+ (`tomllib`). No dependencies. `gh` is optional — without it, CI
status reports `UNKNOWN` rather than being skipped.
