# ADR 0051: Declarative action change templates

- Status: Accepted
- Date: 2026-08-02

## Context

Read-only ActionSpec programs let a user or vendor add diagnostics without a
Rust rebuild. Allowing the same mechanism to run an arbitrary writable program
would create a second configuration API without fresh-state planning,
ownership checks, native validation, independent recovery, or confirmed
commit. Requiring a compiled command for every common policy recipe is also
unnecessarily rigid.

## Decisions

1. Add `mode = "change"` actions whose only effect is to produce input for an
   already supported typed firewall or network planner. A change action cannot
   declare an executable or argv and cannot be model-enabled.
2. The manifest carries a bounded JSON mutation array. Dynamic values use only
   exact object placeholders of the form `{"$input":"name"}`. Placeholder
   substitution preserves the JSON type; there is no textual interpolation,
   shell parsing, path expansion, environment expansion, or caller-provided
   program.
3. Every declared input must be referenced and every placeholder must reference
   a declared bounded string, integer, or boolean input. Template depth, node
   count, mutation count, input count, manifest size, and runtime input size are
   bounded. Registry loading rejects malformed or non-closed mutation shapes.
4. `action plan` expands the template and dispatches it to the same daemon
   firewall/network plan handler used by the built-in CLI. That handler reads a
   fresh inventory, checks object digests and ownership, computes semantic risk,
   creates the executable attachment, and advances the plan to
   `awaiting_approval` atomically.
5. Planning does not grant authority. Apply still requires a boot- and
   actor-bound device-admin capability and one-use approval token. Native
   staging, validation, single-writer serialization, independent rollback,
   post-apply verification, and R3 confirmed commit are unchanged.
6. Direct `action run` rejects change actions. The initial model tool registry
   contains only read-only actions. Future Channel/model planning may be added,
   but execution must continue through the same approval API.
7. Arbitrary writable vendor scripts remain unsupported. A future external
   transaction adapter must provide an independently executable rollback
   contract and equivalent ownership/reinspection semantics before admission.

## Consequences

Users and manufacturers can package reusable operations such as MAC/IP/port
isolation, redirects, managed routes, and other combinations already covered by
the typed platform adapters without changing Rust. The extension remains as
flexible as the safe configuration domains, while unsupported host mutation is
rejected instead of being disguised as an unrestricted root shell.
