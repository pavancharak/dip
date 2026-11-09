# Architecture Decisions

## ADR-0001: Monorepo with pnpm workspaces

Accepted. One repository holds spec, packages and docs so they version together.

## ADR-0002: Strict TypeScript

Accepted. `strict`, `noUncheckedIndexedAccess` and `exactOptionalPropertyTypes` are on.

## ADR-0003: No dependency on Parmana

Accepted. DIP operates and verifies evidence standalone. Parmana lessons are recorded in `docs/PARMANA-LEARNINGS.md`; no code is shared.

## ADR-0004: License Apache-2.0

Proposed. Owner must confirm.

## ADR-0005: Two-outcome authorization

Accepted. The engine returns only ALLOW or DENY. Approval states exist only in the approval workflow (not yet built) and are never authorization outcomes.

## ADR-0006: Canonical encoding restricted to integers

Accepted. Money and all numbers are integers in the safe range; floats are rejected. This avoids the floating-point comparison class and makes the encoding simpler to specify. Consequence: the encoder is not yet claimed to be RFC 8785 conformant, which requires vector testing.

## ADR-0007: Domain-separated signatures and digests

Accepted. Every hashed or signed object uses a `DIP-<TYPE>-V<n>` separator, so signatures for one object type cannot be replayed as another.

## ADR-0008: Ed25519 with Node's built-in crypto

Accepted. Ed25519 is widely supported and Node provides it without extra dependencies. Post-quantum signatures are deferred; Parmana's incidents show that ML-DSA key handling needs its own review.

## ADR-0009: Explicit trust roots; no key discovery

Accepted. A signed object is trusted only if its key is in the caller-supplied trust set and not revoked. Keys are never taken from the object being verified.

## ADR-0010: Fail closed on malformed input

Accepted. Invalid requests and authority declarations throw a `DipError` with a stable code. A throw never produces ALLOW. Only well-formed, verified input is evaluated.

## ADR-0011: Injected clock

Accepted. The engine takes `now` as input. Decisions are reproducible for a given time.

## ADR-0012: Authority registry is in-memory for now

Accepted for Phase 2. Persistence (PostgreSQL, append-only) is a Phase 5/10 item. The registry's semantics (immutable, contiguous versions) are the contract a store must keep.

## ADR-0013: Packaging deviates from the master layout

Accepted. Canonical encoding and hashing live in `packages/crypto` (not a separate `canonical` package) to keep one cryptographic root. `packages/authorization` contains the engine. Other master-layout packages are added when implemented.

## ADR-0014: Patent-risk review pending

Open. Parmana classifies signed execution audit trails, maker-checker enforcement and signal/intent binding as PATENT-RISK. DIP's approval and evidence designs must be reviewed before implementation. Not reviewed yet.

## ADR-0015: Request digest excludes approvalRef

Accepted. An approval is created for request content before its reference exists, so the reference cannot be part of the bound content. Any change to the content changes the digest and invalidates the approval. A different approval reference to an approval bound to the same content is acceptable: that approval already covers the content.

## ADR-0016: Approver keys are part of the authority declaration

Accepted. Each authority lists the approver keys allowed to approve its requests. The engine refuses approvals from any other key, and delegated authorities cannot widen the approver set.

## ADR-0017: Execution is refused unless it is provably authorized

Accepted. The boundary verifies the decision signature under a trusted engine key, requires ALLOW, and requires the exact request digest, authority version and policy version. Refusals are recorded and never reach a connector.

## ADR-0018: A decision authorizes at most one execution; retries need a new decision

Accepted. A decision is consumed before the connector runs. Idempotency protects completed actions: the same key with the same content returns the original result. A retry after failure needs a new decision, which can only be created at a later evaluation time, and reuses the idempotency key so the external system can deduplicate.

## ADR-0019: Timeouts are not failures and not successes

Accepted. A connector that does not answer in time is recorded as TIMED_OUT. The outcome is unknown, so the boundary does not claim success or failure. Resolving it needs the external system's own reconciliation, which is a later phase.

## ADR-0020: The verifier is independent code, not a shared library

Accepted. `@dip/verifier` depends only on `@dip/crypto`. It re-implements the parsing, digest and approval replay from the specification, so a bug in the engine cannot be silently accepted by its own verifier. The cost is duplicated logic, which the verifier's tests check against bundles produced by the real pipeline.

## ADR-0021: Verdict precedence

Accepted. INVALID outranks UNVERIFIABLE, which outranks INCOMPLETE, which outranks VALID. A tampered record is never masked by a missing key elsewhere in the bundle.
