# ADR 0004: First read-only Agent loop

- Status: Accepted
- Date: 2026-07-24

## Context

Text completion alone cannot investigate a device. Allowing a model to emit
arbitrary commands would violate the project's typed-tool, least-privilege, and
embedded resource constraints. Tool-call arguments are untrusted model output
even when a provider accepts a JSON Schema.

## Decisions

1. Add provider-neutral message, function-tool, and tool-call contracts. Support
   tool calls in both ordinary JSON responses and fragmented SSE deltas.
2. Limit provider responses to eight structurally valid function calls, with
   bounded IDs and names. The tiny Agent profile further permits exactly one
   call in a model step.
3. Expose only `diagnose_wan` in the first Agent loop. Its schema accepts an
   empty object and its local implementation always calls the typed diagnostic
   with `active=false`.
4. Validate the tool name and parse the complete JSON arguments again inside
   the daemon. Reject unknown names, malformed JSON, non-object values, and any
   argument field. Reject argument strings above 256 bytes before JSON parsing.
   Provider-side schema enforcement is not a security boundary.
5. Return only normalized WAN summary, findings, completion state, and interface
   to the model. Exclude raw command output and enforce
   `llm.max_tool_context_bytes`.
6. Bound the loop with `llm.max_agent_steps`, one existing LLM semaphore slot,
   and the existing diagnostic semaphore and timeout. Saturating-add token usage
   across model turns.
7. Save the normalized passive diagnostic to volatile SQLite using a derived
   tool-step audit ID. Never persist prompts, model responses, or tool-call
   arguments.

## Consequences

`mbed-agent ask` can now perform an evidence-backed WAN investigation and return
the model's final explanation. It still cannot modify networking, execute a
shell, perform active probes through the model, or invoke any unregistered tool.
Additional read-only tools must each add an explicit schema, local validator,
bounded observation encoder, and contract tests.
