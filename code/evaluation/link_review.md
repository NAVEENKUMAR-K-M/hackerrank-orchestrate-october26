# Evidence-link review

The pre-change reference is the actual 29 completed checkpoints in
`samples-94c954bb5ae439e0`. The three missing samples remain in the denominators.

| Stage | Completed | Step precision | Step recall | Exact sequences |
|---|---:|---:|---:|---:|
| Previous Claude sample checkpoints | 29/32 | 96.6667% | 90.1554% | 17/32 |
| Visual account-link inspection (no prediction change) | 29/32 | 96.6667% | 90.1554% | 17/32 |
| Assignment correction, same 29 intent decisions replanned | 29/32 | 96.6667% | 90.1554% | 17/32 |
| Version-2 fresh Codex audit, before cutoff/proof correction | 28/32 | 97.7654% | 90.6736% | 16/32 |

The replan comparison is a planner diagnostic, not a new model-directed run.
Fresh Codex results are recorded separately after execution; no improvement is
claimed from an unfinished run.

## Images and PDFs

There is one distinct account in the interpreted PNG/PDF artifacts:
`evidence_04`, `account_5762`, linked to `user_11`, Haruka Sato,
`haruka.s1838@zoho.com` and the normalized phone `819076102507`.
The screenshot includes `user_11 · account_5762`. The account already reaches
content-only discovery for its request, with eligible, citable evidence.
All five interpretation-cache occurrences found at the initial scan describe the same account.
The four raw PDFs contain no `account_*` IDs. This inspection adds no account links.
These identifiers belong to the supplied fictional dataset.

## Contested assignments

A scratch analysis script outside the repository enumerated current candidate
edges using only participant data. Under the linker's existing observation,
claim-agreement and co-location filters it found 3 contested singleton account
requests and 14 contested singleton analytics requests. Counts depend on those
filters; the earlier approximate figure of 27 was not reproduced under this definition.
The rivals share report times and authorize deletion. Requests already linked by
content to that resource class are already excluded by the existing linker.
No new text-based exclusion or temporal window was introduced to obtain more links.

The old routine could arbitrarily assign the first of two requests sharing one
sole candidate. The correction requires a complete matching for the connected
group, then keeps only edges whose removal makes a complete matching impossible.
An infeasible group contributes no ownership claims; unrelated groups remain usable.
Regression tests cover conflicting singleton requests, independent groups, and
partially forced assignments.

## Attachment classification

Extraction version 2 distinguishes an uploaded file from a shared conversation.
A single support resource in a PDF/image explicitly described by attachment
properties, upload history, a PDF filename and a customer uploader is classified
as `SUPPORT_ATTACHMENT`. Generic customer-request prose inside that file does not
make the file a shared conversation. Conversation text merely mentioning a file
continues to use `SUPPORT_MESSAGE`. Tests verify both cases and the DELETE policy
for the attachment. Fresh visual extraction and model-directed sample metrics
must confirm the effect before any new full audit or packaging.

## Evidence availability and redaction proof

The fresh model interpretation initially added a redaction verification from a
customer-reference registry screen. Visual inspection showed a stable customer
key and linked business references, but no name/email/phone/hash field readbacks.
Extraction version 3 marks that situation uncertain and requires quoted removal
readbacks for visual tombstone redaction. The new regression test checks both an
insufficient reference view and a sufficient null-field readback.

Review also found that the previous observation filter admitted artifacts captured
after the case cutoff. AGENTS.md section 6.2 requires information available by the
cutoff, so eligibility now checks both observation and capture timestamps. A test
confirms that a late export describing an earlier deletion cannot erase an eligible
surviving record from the audit. This correction is required by the contract even
where excluding late captures reduces sample recall.
