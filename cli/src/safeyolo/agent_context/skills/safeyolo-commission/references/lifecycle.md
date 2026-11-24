# Supervise and resume the same task worker

Use the existing selected worker, durable identity, approved role, workspace
and checkpoint. Keep task progress in native Coord Work. The host owns sandbox
start and stop; the guest supervisor owns model turns and actionable attention.

Read the current
[worker lifecycle reference](https://github.com/craigbalding/safeyolo/blob/master/docs/worker-lifecycle.md)
for configuration, native calendar behavior, scope and request semantics.
Choose on-demand, continuous or scheduled operation from the operator's intent.
Do not turn example overnight times, recurrence, completion stopping or deadlines
into requirements for every worker.

For an authorized change, use the selected host's agent lifecycle commands
or the existing exact policy proposal/adoption owner. Explain the incremental
activation and cutoff effects in the accepted plan. No arbitrary host command,
Admin credential or other-worker targeting belongs in a guest request.

During execution, create and claim authorized self-assigned Work. Consume its
canonical attention, retain its actual outputs and explicitly complete the
claim. Read required checks and acceptance separately. On interruption, inspect
the existing Work and retained artifacts before continuing. Reconcile uncertain
external effects instead of blindly repeating them.

For selected completion-led stopping, call read_lifecycle. After the scoped
work and required independent acceptance are complete, create and claim a
self-assigned shutdown Work item with
external_ref = safeyolo:lifecycle/self-stop in the configured completion room.
Choose an operation ID, then call request_self_stop with that Work ID.
The host supplies the current scope to the adopted check and owns the stop.
Do not report an accepted request as a completed shutdown.

After an uncertain reply or a subsequent activation, use
read_self_stop_request with the original operation ID. Read the host-observed
result before completing the shutdown Work or proposing another effect.
A mandatory cutoff can stop unfinished work; it does not complete or cancel
that work. Resume the retained assignment on the next eligible activation.
The operator's selected task policy owns prioritization.
