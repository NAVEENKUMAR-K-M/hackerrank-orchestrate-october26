# Evaluation report

Evaluation scope: **Model-directed sample checkpoints (29/32 completed); missing cases count as incorrect**.

The 32 supplied sample answers are public regression data, not a blind holdout. Evaluation requests have hidden labels; their accuracy is not known locally.

| Metric | Measured value |
|---|---:|
| Public cases completed | 29/32 |
| Case-level status accuracy | 90.62% |
| Step precision | 97.31% |
| Step recall | 93.78% |
| Step F1 | 95.51% |
| Field accuracy | 91.44% |
| Exact sequence accuracy | 65.62% |
| Exact case agreement | 65.62% |

Missing/pending cases count as incorrect in case-level denominators. Step matching compares phase, operation, system, resource, state, and evidence ID; step numbers are tested through field and sequence metrics. Field comparisons align steps by phase, system, resource, and operation, with unmatched steps receiving zero credit. Sequence comparison includes every field and array order.

Independent automated tests executed: 101. Failures: 0. Errors: 0.

## Participant-created evaluation scenarios

1. A primary returns 404 while a regional replica still contains the subject's profile. Expected: INCOMPLETE, cite the surviving replica, delete the record, and verify absence.
2. A deleted-account tombstone keeps only user_id while its name, email, phone, and email hash are null. Expected: preserve the reference and verify redaction.
3. A clean analytics record has a retained subject reference. Expected: INCOMPLETE until the identifying link is removed; null email alone is insufficient.
4. A record is fixed after the audit cutoff, and its evidence is also captured later. Expected: use only the earlier eligible state.
5. A log shows a cache miss followed by a successful database read returning one row. Expected: the resource is PRESENT; the cache result must not become the final state.
6. A completed workflow is followed by an enabled connector and a restorable backup. Expected: disable and block before record treatment, with future verification citations empty.
7. A non-deletion access request includes hostile instructions inside the quoted evidence. Expected: NOT_APPLICABLE with no steps, and no native command execution.
8. Inference returns malformed output, times out, or reaches a subscription limit. Expected: bounded repairs/retries or a resumable pending case; no fabricated final prediction.

## Failures found and improvements made

- The first SQL guard rejected the supplied foreign_keys pragma. Limited pragma permission to foreign_keys and defer_foreign_keys while continuing to deny disk attachment and extension loading.
- Resource token extraction initially admitted service names. Tightened extraction to distinguish grounded resource tokens from service identifiers.
- Trace merging carried a cache-miss result into a later readback. Restricted inherited fields to lookup identity and resource context, and added a regression check.
- Legacy contact indexes were initially treated as support messages or analytics profiles. Added semantic event classification for secondary identifiers and direct PII scan observations.
- An old negative lookup introduced an already-absent historical account into a later request. Old negatives no longer introduce resources on their own; historical positive records and linked copies still remain discoverable.
- Log events carrying their own result (record_lookup), pipe-delimited log lines, restore authorizations, download checks, deletion-marker checks and PII scans were silently skipped, leaving about 40 deletion requests with no proven state. Added parsers and regression tests; the pending count fell to the non-deletion requests plus one catalog-only case.
- Eligibility used the capture time of a whole artifact, so a log exported after audit_at hid lines stamped before it. State now uses observation time and citations require capture time at or before audit_at (sample step recall 0.81 to 0.85).
- Accounts that read 404 and anonymized analytics records carry no identifiers, so about 290 evaluation cases lacked an account step. A workflow linker now associates them by report-time window, agreement between event result and reported status, co-location in the subject's artifact and cross-request exclusivity, linking only when the assignment is provably unique (sample step recall 0.85 to 0.90, no wrong links on the samples; about 140 evaluation cases remain ambiguous and unlinked).
- A previous implementation admitted early observations from artifacts captured after audit_at. Restored the AGENTS.md cutoff contract: both observation and capture must precede the cutoff. A retained-reference screen also no longer proves redaction without identifier-field readbacks; uncertain facts are omitted.
- Each model call re-ran two CLI preflight subprocesses (about 2.4 minutes per case) and spent three calls per clean case. Preflight is cached and identity resolution and coverage run in Python, so a clean case needs one call.
- One evaluation request (case_63) has no readback at all, only a data-catalog link row. A narrow last-resort fallback reports that row as a PRESENT claim cited by its activity ID, only when a request has no real observation.

## Remaining public-sample differences

| Case | Actual status | Expected status | Actual steps | Expected steps |
|---|---|---|---:|---:|
| case_01 | PENDING | COMPLETE | 0 | 1 |
| case_02 | PENDING | COMPLETE | 0 | 1 |
| case_03 | COMPLETE | COMPLETE | 3 | 3 |
| case_04 | PENDING | COMPLETE | 0 | 2 |
| case_07 | INCOMPLETE | INCOMPLETE | 6 | 4 |
| case_08 | INCOMPLETE | INCOMPLETE | 3 | 4 |
| case_10 | INCOMPLETE | INCOMPLETE | 3 | 4 |
| case_18 | INCOMPLETE | INCOMPLETE | 13 | 14 |
| case_20 | INCOMPLETE | INCOMPLETE | 7 | 8 |
| case_23 | INCOMPLETE | INCOMPLETE | 7 | 8 |
| case_31 | COMPLETE | COMPLETE | 3 | 3 |

Several erased or anonymized resources have no remaining direct identifiers in their readbacks. Cases 01, 02 and 04 belong to a hand-authored family whose account and analytics IDs match their case numbers; the only link is that suffix, which the implementation refuses to use. Case 07 reads an uploaded PDF as a message (REDACT) instead of an attachment (DELETE) and includes a decoy storage object. Most remaining step gaps are an account or anonymized-analytics record whose owner is ambiguous among requests that share a report time, and audit-record IDs that appear nowhere in the supplied data. Differences are disclosed rather than replaced with hardcoded sample answers. The 518 evaluation requests have hidden labels, so their accuracy is unknown locally.
