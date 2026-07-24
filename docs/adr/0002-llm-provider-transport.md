# ADR 0002: Bounded LLM provider transport

- Status: Accepted
- Date: 2026-07-24

## Context

The first LLM integration must work with hosted and self-managed
OpenAI-compatible endpoints without giving the model direct tool access. It
must also preserve the daemon's hard memory limits and Rust 1.85 MSRV.

## Decisions

1. Keep provider wire types in the isolated `agent-provider` crate. The local
   IPC exposes only provider-neutral completion data.
2. Start with non-streaming `chat/completions`. Tool calling, streaming event
   normalization, provider routing, retries, and conversation persistence are
   separate later slices.
3. Use reqwest without default features, rustls without an automatically
   selected crypto provider, and the ring provider. HTTP redirects are disabled
   so bearer credentials cannot be forwarded to another origin.
4. Reject an enabled daemon configuration unless the endpoint uses HTTPS and
   credentials and model are present. Provider construction also rejects URL
   credentials, queries, fragments, and missing hosts.
5. Bound serialized requests, declared and chunked response bodies, connection
   time, request time, output tokens, and concurrent calls. Do not persist
   prompts or responses in the volatile database in this slice.
6. Keep API keys in a debug-redacted configuration type. The daemon owns the
   key; local CLI clients never load it.
7. Lock Rust 1.85-compatible ICU transitive versions in `Cargo.lock`.

## Measured result

On the development macOS x86_64 host, the stripped size-optimized release binary
grew from 570,864 bytes to 3,379,472 bytes. The initially tested AWS-LC build was
4,431,184 bytes, so ring saved 1,051,712 bytes. Target OpenWrt architectures
still require SDK builds and RSS measurements before setting final package
budgets.

## Consequences

The daemon can now perform one bounded provider call through
`mbed-agent ask`, while deterministic local diagnostics continue to work when
LLM support is disabled or unreachable. The current completion is not yet an
Agent loop and cannot request or execute tools.
