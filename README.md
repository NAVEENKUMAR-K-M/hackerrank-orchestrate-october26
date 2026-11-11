# Ghost Data Still Exists

An evidence-grounded deletion-audit agent for HackerRank Orchestrate, October 2026.
It reconstructs current and historical identities, investigates participant evidence,
applies the supplied retention policy, and produces findings, remediation, and
verification steps at each request's audit_at cutoff.

## Validation status

The previous Claude run audited all 518 requests (517 through the model-directed loop and one through a
documented catalog-only fallback), validated 3,050 steps and 1,141 citations, and wrote the
root output.csv. On the 32 public samples the Claude-backed agent completed 29 with 100% status
accuracy on those, step precision 96.7%, recall 90.2%, and 17 exact sequences; cases 01, 02 and 04
stay pending because their only link is a number suffix. Hidden-label accuracy for the 518
requests is unknown locally. See [the evaluation report](code/evaluation/evaluation_report.md)
and [usage report](code/evaluation/usage_report.md) for definitions, failures found and cost.

Known limits: about 140 evaluation cases have an identity-free account or anonymized analytics
record that cannot be uniquely tied to one request (requests sharing a report time), so those
steps are omitted rather than guessed; audit-record IDs that appear nowhere in the data cannot be
reported.

## Setup

Requirements: Python 3.12 or later and Claude Code CLI (`claude`, tested with 2.1.302)
signed in with a Claude subscription. The CLI must support `-p`, `--json-schema`,
`--tools ""`, `--safe-mode`, and stream-json input for screenshots.

Create an environment and install the pinned dependencies:

~~~powershell
python -m venv .venv
./.venv/Scripts/python.exe -m pip install -r requirements.txt
~~~

On macOS/Linux, use .venv/bin/python instead. Dependencies are Pydantic, pypdf,
pypdfium2, and Pillow. SQLite and unittest are part of Python.

Sign the CLI into your own Claude account (once):

~~~powershell
claude auth login
claude auth status
~~~

If `claude` is not on PATH, set CLAUDE_BIN to its executable's absolute path.
Credentials stay in Claude-managed storage; never copy them into this repository.


~~~powershell
./.venv/Scripts/python.exe code/main.py preflight
~~~

The runtime requires Claude subscription authentication and strips
ANTHROPIC_*, OPENAI_*, cloud-provider, and other API-key variables from the child
environment, so it cannot silently switch to pay-as-you-go billing. Subscription
usage limits still apply. A limit hit checkpoints the run; rerun the same command
after the limit resets and completed cases are reused.

## Run

Commands resolve the repository root from the entry point. Optional --root PATH
and --model MODEL precede the subcommand. The default model is `sonnet` (Claude Sonnet 5.5) at medium effort.

~~~powershell
./.venv/Scripts/python.exe code/main.py index
./.venv/Scripts/python.exe code/main.py index --vision
./.venv/Scripts/python.exe code/main.py audit --samples --smoke
~~~

The first command makes no model calls. The second interprets documents and
screenshots using the subscription and caches grounded facts.

Use --case-id CASE_ID or --limit N on audit for a limited investigation.
Run state, extracted facts, responses, tool decisions, and measured usage live
under .runs/. Unchanged commands resume completed cases. Input, source, policy,
prompt, parser, model, or budget changes invalidate appropriate caches.
Completed checkpoints are rechecked against current evidence before reuse.

~~~powershell
./.venv/Scripts/python.exe code/main.py audit
./.venv/Scripts/python.exe code/main.py validate
./.venv/Scripts/python.exe code/main.py package
~~~

The final output is repository-root output.csv, not dataset/output.csv. It has
exactly case_id,deletion_status,steps_json, sorted by case ID, with one row per
evaluation request. All steps use the prescribed fields, operations, states,
citations, and ordering. NOT_APPLICABLE has an empty array.

Exit 0 means completion. Exit 2 means setup, validation, quota, or unresolved
investigation prevented completion. Limited/pending runs never publish the final CSV.

## Investigator architecture

Python controls the investigation loop. Each Claude response is a strict JSON
decision selecting up to six domain tool calls or proposing finalization. An
explicit Python handler table dispatches calls; model text never becomes code.

| Tool | Executed behavior |
|---|---|
| resolve_identity | Resolve current and historical identifiers at the cutoff |
| search_evidence | Exact identity/resource retrieval and paginated source-text search |
| inspect_resource | Inspect readbacks, replicas, and operational claims |
| read_artifact | Read source text or request constrained evidence interpretation |
| get_policy | Return supplied category rules and conditions |
| check_coverage | Identify missing account proof, states, or interpretation |

The model first determines whether deletion is authorized. Non-deletion requests
finish without probing identity or generating deletion actions. Deletion cases
must resolve identity, inspect coverage, and accept an evidence-backed plan.
Uncertain intent, missing proof, and rejected validation consume bounded repair
opportunities and remain pending when unresolved.
The model can stop early with specific missing facts. A persistent search journal
tracks unread result pages across truncated conversation history.

Defaults: eight decisions per case, two validation repairs, 180 seconds per
invocation, 15 minutes per case, one inference process at a time. Transient errors
receive at most two retries. Authentication and subscription-limit errors stop
new inference. These are application limits, not hidden backend call counts.

Claude runs through `claude -p` in an isolated temporary directory with every built-in
tool disabled (`--tools ""`), safe mode, no session persistence, no slash commands and no
setting sources; the subscription login is used and API keys are stripped. Python owns domain
tools; unexpected native tool events are rejected. Prompts and evidence are untrusted
inputs. Capability tests do not establish complete prompt-injection resistance.

## Evidence and policy

The prediction loader allowlists participant inputs and rejects sample answers.
Evidence paths must stay beneath dataset/evidence/. SQL executes only in isolated
in-memory databases; disk attachment, extension loading, and unsafe pragmas are
denied. Log traces preserve lookup identity while excluding stale cache results.

Every observation carries a file ID, source location, capture time, observation
time, system, resource, category, and replica. Exact current/historical emails,
hashes, and normalized phones provide identity matches. Similar names, numeric
suffixes, filename patterns, and case ordering do not establish ownership.
Operational activity can discover relationships; success statuses do not prove state.

Time handling distinguishes two clocks. A recorded state is usable when its observation
time is at or before audit_at, even if the log or export containing it was captured later
(a central log export captured after the audit still describes earlier events). A step may
cite an artifact only when the artifact itself was captured at or before audit_at; the
planner picks a citable observation with the same verdict, and a COMPLETE case whose
only proof is uncitable stays pending rather than citing future evidence.

Absence requires an explicit not-found readback or a covering inventory. Mixed
inventories contribute negatives only when their contents establish subject
coverage. An old negative lookup alone does not introduce an already-absent
resource into a later request. Historical positives and linked copies remain searchable.
A later primary readback does not erase a surviving regional replica.

Policies include DELETE, REDACT, ANONYMIZE, RETAIN, disabling flows, and blocking
restores. Tombstones preserve stable references while removing direct identifiers.
Required retained records remain available. The planner follows the mandated phase
and operation order. Future actions have empty citations; completed verification
cites the observation establishing the required state.

## Tests and evaluation

~~~powershell
./.venv/Scripts/python.exe -m unittest discover -s code/tests -v
./.venv/Scripts/python.exe code/evaluation/main.py
~~~

The evaluator runs independent tests and measures an explicitly labeled evidence-only
diagnostic against all 32 public samples. Missing cases stay in denominators.
After a real model-backed sample run, evaluate its generated CSV:

~~~powershell
./.venv/Scripts/python.exe code/evaluation/main.py --predictions PATH_TO_GENERATED_SAMPLE_CSV
~~~

Metrics cover status, step precision/recall/F1, fields, exact sequences, and exact
case agreement. The Markdown report includes definitions, participant-created
scenarios, actual failures, and implemented changes. Only evaluation code reads
expected sample answers. Hidden-label evaluation accuracy is unavailable locally.

The [usage report](code/evaluation/usage_report.md) reports observed invocations,
tokens, caches, and subscription assumptions. Cached input is a subset of input
tokens and is not added twice. Failed runs are explicitly interim. Final usage
must come from the production run that generated the complete output.

## Development transcript and artifacts

Follow AGENTS.md for the shared root log.txt. Preserve prior entries and their
retrospective labels. Included development turns record the actual user prompt,
factual actions/results, and harness/model identifiers from authoritative session
metadata. Explicitly excluded turns are not backfilled. Runtime audit traces are
separate from human development turns.

code.zip contains source, prompts embedded in Python, pinned requirements, README,
and evaluation Markdown reports. Reports are included under code/evaluation/ and
archive-root evaluation/ to satisfy both documented layouts. Dataset files,
environments, caches, credentials, transcripts, and nested archives are excluded.
Packaging validates the completed output and checks archive integrity and hashes.

Submit code.zip, root output.csv, and root log.txt as the chat transcript. Preserve
relevant original traces separately as described in agent_trace_instructions.md.
The repository does not configure an October deadline.

Challenge: https://wwww.hackerrank.com/contests/hackerrank-orchestrate-october26/challenges/ghost-data-still-exists

## Runtime migration and current review

The active inference adapter is the Claude Code CLI (`claude -p`) with `sonnet`, medium effort,
and Claude subscription authentication. There is no API-key fallback. Provider/model/effort
changes invalidate model response caches. The extraction cache version is bumped when
classification rules change.

Both observation and capture timestamps must be at or before audit_at. Later captures
cannot change the answer. Extraction version 3 requires field-level readbacks before
a visual tombstone can be marked REDACTED; a customer-key screen alone is insufficient.
