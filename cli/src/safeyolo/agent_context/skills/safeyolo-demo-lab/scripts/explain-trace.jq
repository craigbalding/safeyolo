def reason_meaning:
  if .reason == "prior_response" then
    "An earlier addon already produced a response, so this hook deferred."
  elif .reason == "policy_disabled" then
    "Policy disabled this addon for the current scope, so it did not evaluate the flow."
  elif .reason == "addon_disabled" then
    "The proxy configuration disabled this addon, so it did not evaluate the flow."
  elif .reason == "probe_sink_failed" then
    "The reserved pipeline probe had no working local sink. SafeYolo stopped it before transport."
  elif .reason == "probe_reached_upstream" then
    "The reserved pipeline probe reached the transport backstop. Its local sink did not stop it earlier."
  elif .reason then
    "The hook did not evaluate the flow. SafeYolo recorded the reason shown above."
  else
    "The hook did not evaluate the flow, but the trace did not include a reason."
  end;

def outcome_meaning:
  if .addon == "credential-guard" and .outcome == "no_detection" then
    "The addon scanned credential-bearing headers and found no configured credential."
  elif .addon == "credential-guard" and .outcome == "detected" then
    "The addon detected one or more configured credentials. Policy can now evaluate their use."

  elif .addon == "pattern-scanner" and .outcome == "no_rules" then
    "No content-scan rules were configured, so this hook had nothing to match."
  elif .addon == "pattern-scanner" and .outcome == "no_match" then
    "Content-scan rules were active, but none matched this request or response."
  elif .addon == "pattern-scanner" and .outcome == "match_logged" then
    "A content-scan rule matched in warn-only mode. SafeYolo logged it and did not block it."
  elif .addon == "pattern-scanner" and .outcome == "match_blocked" then
    "A content-scan rule matched and produced a block."

  elif .addon == "network-guard" and .outcome == "allowed" then
    "The network policy allowed this destination, so the request could continue."

  elif .addon == "circuit-breaker" and .outcome == "allowed" then
    "The circuit was closed, so recent upstream failures did not stop the request."
  elif .addon == "circuit-breaker" and .outcome == "excluded_domain" then
    "This destination is excluded from circuit-breaker checks."
  elif .addon == "circuit-breaker" and .outcome == "success_recorded" then
    "The response followed the success path. Existing circuit state was updated when present; this outcome alone does not prove a stored mutation."
  elif .addon == "circuit-breaker" and .outcome == "failure_recorded" then
    "The response counted as an upstream failure and updated circuit health."
  elif .addon == "circuit-breaker" and .outcome == "status_no_action" then
    "The response was a non-429 client error. It did not change circuit state."
  elif .addon == "circuit-breaker" and .outcome == "prior_block" then
    "An earlier SafeYolo addon blocked the flow, so this response did not count against the upstream circuit."

  elif .addon == "test-context" and .outcome == "allowed" then
    "A valid test-context header was present and SafeYolo applied it to this flow."
  elif .addon == "test-context" and .outcome == "not_target_host" then
    "This host did not require test context, and no context header was present."
  elif .addon == "test-context" and .outcome == "response_recorded" then
    "The flow had test context, so SafeYolo recorded its completed response event."
  elif .addon == "test-context" and .outcome == "not_applicable" then
    "The flow had no test context, so there was no test response event to record."

  elif .addon == "service-gateway" and .outcome == "not_a_gateway_request" then
    "No sgw_ capability token was present. This was not a service-gateway call, so the addon passed it through."
  elif .addon == "service-gateway" and .outcome == "injected" then
    "The service gateway accepted the scoped capability and injected the upstream credential."
  elif .addon == "service-gateway" and .outcome == "not_a_gateway_response" then
    "The flow had no gateway grant, so response-side grant handling did not apply."
  elif .addon == "service-gateway" and .outcome == "grant_consumed" then
    "A successful gateway response consumed its one-use grant."
  elif .addon == "service-gateway" and .outcome == "grant_retained" then
    "The gateway grant remained available because it was not a successful one-use response."

  elif .addon == "probe-sink" and .outcome == "probe_terminated" then
    "The local probe sink returned the diagnostic response. No upstream service was contacted."
  elif .addon == "probe-sink" and .outcome == "probe_preempted" then
    "An earlier addon already answered the probe, so the sink recorded that fact without replacing the response."

  else
    "SafeYolo recorded this addon-specific outcome. This demo has no maintained explanation for the value."
  end;

def step_meaning:
  if .state == "evaluated" then
    outcome_meaning
  elif .state == "bypassed" then
    reason_meaning
  elif .state == "error" then
    if .reason then
      "The addon hook raised \(.reason). This is an error, not a normal non-applicable result."
    else
      "The addon hook raised an error. The trace did not include its type."
    end
  elif .state == "not_loaded" then
    "SafeYolo expected this addon, but it did not run for this traced request."
  else
    "SafeYolo recorded this state. This demo has no maintained explanation for the value."
  end;

def observed_details:
  if ((.details? // null) | type) == "object" and ((.details | length) > 0) then
    " details=\(.details | tojson)"
  else
    ""
  end;

def format_meaning:
  gsub("\\. "; ".\n              ");

def render_step($number):
  "[\($number)] \(.addon) / \(.hook // "no hook")\n" +
  "    observed: state=\(.state)" +
  (if .outcome then " outcome=\(.outcome)" else "" end) +
  (if .reason then " reason=\(.reason)" else "" end) +
  observed_details + "\n" +
  "    meaning:  \(step_meaning | format_meaning)\n";

(.steps // []) as $steps |
"state=evaluated means the named hook ran and reported an outcome.\n" +
"It does not, by itself, mean that SafeYolo allowed or blocked the request.\n",
"Trace coverage\n" +
"    observed: truncated=\(.truncated) not_loaded=\((.not_loaded // []) | length)\n" +
"    meaning:  " +
(if .truncated then
   "The trace reached its step limit, so later steps can be absent."
 else
   "The trace did not reach its step limit."
 end) +
(if ((.not_loaded // []) | length) == 0 then
   " Every expected trace addon reported.\n"
 else
   " The missing expected addons are explained below.\n"
 end),
($steps | to_entries[] | . as $entry |
  $entry.value | render_step($entry.key + 1)),
((.not_loaded // []) | to_entries[] | . as $entry |
  $entry.value | render_step(($steps | length) + $entry.key + 1))
