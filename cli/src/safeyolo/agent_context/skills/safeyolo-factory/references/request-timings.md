# Passive request timings

Collect timings as a byproduct of useful agent and human-persona journeys.
Keep the journey's ordinary behavior. Do not replace it with a benchmark,
additional load, a different client or a proxy bypass.

## Contents

- [Collect each attempt](#collect-each-attempt)
- [Use existing observations accurately](#use-existing-observations-accurately)
- [Compare spikes and trends](#compare-spikes-and-trends)

## Collect each attempt

Start the selected observer before the first operation. Retain a timing record
for every issued request, including retries, denials, errors, timeouts and
cancelled requests. Do not sample only successes or unusually slow requests.
Reconcile the requests issued with the records captured. Report missing
requests, unavailable fields and unknown coverage explicitly.

Use existing client or harness instrumentation for monotonic elapsed time where
available. Time human operations separately: one CLI command or approval
journey can contain several requests. Record user think time, approval waiting
and agent reasoning separately from product/request latency when observable.
Do not invent that separation when the observer cannot measure it.

Preserve these facts when the source exposes them:

| Fact | Purpose |
|---|---|
| Journey, operation and attempt | Correlate retries and each request with the user-visible action. |
| Instance, runtime and native request/connection identity | Keep restarted runtimes and concurrent requests distinct. Preserve supplied IDs rather than inferring matches from timing alone. |
| Timestamp, clock source, units and measurement boundaries | Locate a spike and interpret exactly what an interval includes. Use monotonic intervals within one clock domain when available. |
| Method, destination/route, transport and streaming mode | Compare requests performing similar work. |
| Response-head/first-output and terminal observations | Separate responsiveness from body generation, transfer and stream lifetime. State which event was actually measured. |
| Outcome, error, attempt number and available byte counts | Retain failures and differences in work size instead of hiding them in averages. |
| Product/configuration revision and material load context | Identify changes in the proxy, environment, concurrency or client. |

Retain raw timestamps alongside any derived durations. Null remains unavailable;
it is not zero. An unfinished stream has no completed duration. Record timeout
and cancellation elapsed time as that attempt's observed limit, not as a
successful response latency. Keep backwards wall-clock intervals invalid.

Use the existing evidence location and retention policy. Keep observation
outside the tested process where practical. Record collection failure and
observation loss, including a proxy restart. Preserve relevant raw evidence
under existing access rules; timing collection does not require new payload
capture or broader data access.

## Use existing observations accurately

Read the installed version's help and the bound checkout's
[native-observation guide](https://github.com/craigbalding/safeyolo/blob/master/docs/native-observations.md)
before selecting a source. The source guide at the tested revision is the
authority; the following distinctions describe the current implementations.

| Source | Available measurement and limit |
|---|---|
| Client/harness observation | Caller-visible elapsed time when instrumented. It can include connection setup, upload, policy/approval waiting, upstream work, transfer and local processing. State the actual boundaries. |
| Native live traffic view | Hypertext Transfer Protocol (HTTP) lifecycle fields include `started`, `request_completed`, `response_head_observed`, `response_completed`, `ended` and available upstream connection timestamps. These are wall-clock seconds, not isolated proxy processing time. |
| Retained FlowStore rows | `ts_start` and `ts_end` are Unix epoch milliseconds; `duration_ms` is their elapsed-millisecond difference. The retained start is after request ingress end-of-message; upload and earlier processing are excluded. Eligibility and evidence-owner scope limit coverage. |
| Native observations report | Runtime identity, aggregate transport measurements and observation-loss counters. These do not provide a per-request history or explain one request's latency. |
| Existing metadata capture | Canonical records can preserve runtime-relative monotonic timestamps, identity and explicit gaps. Capture is an explicit configuration choice, not a default adapter or an automatic HTTP latency series. |

On the authorized owning host, use the installed command-line interface (CLI)
for the selected instance.
Here `instance_root` is that instance's existing root and `test_agent` is the
agent exercising the journey. These commands read current observations:

```sh
safeyolo --instance-dir "$instance_root" traffic list --agent "$test_agent" --json
safeyolo --instance-dir "$instance_root" observations --json
```

The first command returns the current bounded live view. The second identifies
the current runtime and its aggregate observations. Collect applicable data
throughout the bounded journey with an existing recorder or observer. Record
the observer, collection interval, limitations and overhead where measurable.
Changes in collection can affect latency comparisons. Start/end snapshots alone
do not establish that every request was retained. Ordinary sandbox agents use
their own authorized Agent application programming interface (API) views; they
must not obtain the host Admin token or probe the host Admin API to collect timings.

The live view is in memory. Completed rows can be pruned, and CONNECT and
reserved internal-host requests are excluded. Reserved operator/API requests,
unfinished streams and pre-context failures can therefore need client-side
measurement. FlowStore is also not a complete request census. Follow its
owner-scoped search and pagination through the
[Agent API guidance](../../safeyolo/references/agent-api.md); one result page
is not a complete export. An agent-name filter does not grant another agent's
evidence access.

If an existing capture is selected, retain its runtime/session identity and
gap/loss records. Starting capture can require configuration and restart; use
the existing authorized lifecycle and record the changed conditions. Do not
silently reconfigure or restart a live factory merely to obtain timings.
Per-hook tracing is a separate diagnostic attempt with its own overhead and
scope, not a replacement for passive journey measurements.

Record any uncovered request or missing timing stage as an instrumentation
gap. The functional exercise can still finish; its timing coverage remains
incomplete. Do not label a bounded live view, FlowStore export or aggregate
histogram as complete per-request evidence.

## Compare spikes and trends

Preserve the ordered individual observations. Compare like method/route,
transport, streaming, outcome and workload-size groups. Record sample counts,
time windows, revision and material differences in concurrency, connection
reuse and warm/cold state. Keep failures and retries visible separately.

For supported comparisons, report typical and tail latency with counts, the
largest individual spikes, and absolute and relative changes from the prior
comparable window. Distinguish an isolated slow request from a repeated or
sustained shift. Do not claim a trend from one observation or meaningful tail
precision from a few samples. Use an established requirement or explain the
practical impact when calling a change material; do not invent a universal
failure threshold.

Name intervals for the events they measure. For example,
`response_head_observed - started` measures the observed path to response head;
it is not proxy self-time. Long response bodies and WebSocket lifetimes are
different from time to first useful output. Preserve those distinctions.

A slowdown is a reason to investigate attribution. Compare the available
client, upstream, policy/approval and proxy observations before naming a
cause. Do not subtract incompatible clocks, scopes or aggregate histograms to
manufacture proxy overhead. Mark an unlocated delay as unlocated. Continue
ordinary dogfooding while a focused follow-up resolves the attribution.
