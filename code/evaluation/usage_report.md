# Usage report

Run: `full-1dae3e6ff8bc4831`. Final 518-case output generated: **no**.

Completed requests in this run: 0. Provider: Anthropic through the Claude Code CLI (`claude -p`) with a Claude subscription login.

| Model requested | CLI invocations | Failed invocations | Model turns | Uncached input | Cache-write input | Cache-read input | Output tokens | List-price cost (USD) | Application cache hits |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| gpt-6-sol | 10 | 0 | 10 | 130567 | 0 | 26112 | 6167 | 0.0000 | 1 |
| Overall (this run's own invocations) | 10 | 0 | 10 | 130567 | 0 | 26112 | 6167 | 0.0000 | 1 |

Total reported tokens: 162846. Per-request averages are unavailable because no requests completed.

Input is split into the three classes the CLI reports: uncached input, cache-write input and cache-read input. Cost is the CLI-reported list-price equivalent of those tokens at standard rates. The run authenticates with an existing Claude subscription and removes provider API keys from the child environment, so the incremental API charge is $0; the list-price figure is an estimate of what the same usage would cost on pay-as-you-go rates, not an invoice. Cache-hit rows are application-level replays and cost nothing.

Model names above are the explicit selections passed to the CLI; resolved model identifiers are retained in usage.jsonl. CLI invocations and reported turns are observable; backend request counts that the CLI does not expose are not invented. Cached rows keep their originating usage under `origin_usage`; that earlier usage belongs to the run that created it.

Started invocations without a closing event: 0. Their unreported tokens are unknown, not assumed to be zero.

This is an interim report. It does not claim a completed full-dataset production run.
