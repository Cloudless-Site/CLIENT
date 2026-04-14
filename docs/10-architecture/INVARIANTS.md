# Cloudless Invariants

This document collects the invariants that should remain stable across audits, refactors and functional patches.

## Work invariants
- do not invent features, targets, workflows or runtime paths not present in sources or explicitly decided
- modifications must preserve behavior unless explicitly intended
- stylistic refactors and functional changes should remain separate when possible
- every step should leave the tree in a compilable state
- verify real Makefiles and runtime paths before structural changes

## Architectural model
- the canonical runtime model is `session -> service -> endpoint`
- `src/control` owns control-plane commands, SSH handling and validated mutations
- `src/dataplane` owns real traffic forwarding
- `src/store` owns SQLite persistence and schema logic
- `src/core` owns runtime entities and orchestration
- `src/edge` owns scripting runtime integration
- `src/common` provides shared primitives and support code

## Control plane
- every mutating action flows through the control plane or dashboard IPC path
- dashboard routes do not mutate persistent state directly; they delegate to IPC
- an authenticated control-plane session owns a single active identity snapshot at a time
- admin-only actions require an authenticated admin context at the point of execution
- the Node dashboard must not become a second source of truth
- new dashboard flows must not bypass core validation

## Session, service, endpoint model
- a session is the authenticated runtime container for a connected client
- a service belongs to exactly one owner fingerprint
- a service is attached to one live session at creation time, even if it is later queried from other surfaces
- endpoint presentation is derived from service state, not stored as an independent source of truth

## Pair
- pair codes are short-lived activation material, not durable identity
- pair SIDs are unique while active
- pair session creation, rendering, keepalive and disconnect must cleanup activator bindings on failure
- pair HTTP flows must never leave an activator bound without a corresponding live pair session

## Dataplane
- dataplane workers move traffic; they do not own durable policy state
- dataplane must not perform SQLite operations in the hot path
- dataplane must not depend on slow filesystem operations in the hot path
- dataplane workers must avoid blocking operations
- accept, TCP and UDP queues are bounded and must fail with explicit drop or backpressure behavior instead of silent unbounded growth
- accept path should remain lightweight and delegate work to workers
- dataplane shutdown or backpressure must not corrupt store state

## Store
- the store is the durable source of truth for users, domains, ACL state and policy tables
- SQLite belongs to the store/control plane, not the dataplane
- store entrypoints must not use a closed database handle
- caches must not change database semantics
- verification state transitions move forward deliberately; verification is not inferred from transient dataplane activity
- initialization procedures intended as bootstrap must remain idempotent

## Workspace and runtime
- `Cloudless` is the source tree
- `Cloudless-work` holds build artifacts
- `Cloudless-permanent` holds persistent development assets
- runtime root is `/var/lib/cloudless`
- runtime `conf`, `private`, `hooks` and `scripts` come from the defined workspace source of truth
- `/var/lib/cloudless/db` is runtime-only

## Refactor boundaries
- do not change API ownership or lifetimes without explicit analysis
- do not refactor third-party code during style changes
- do not introduce new architecture purely for cleanup

## Observability
- the ring logger is best-effort and in-memory; it is useful for crash-adjacent diagnosis but not a durable audit ledger
- log readers may miss entries under sustained pressure and must tolerate the explicit slow-reader marker
- build, release and test paths should emit enough metadata to identify the source tree version that produced an artifact

Invariants may degrade under extreme load but must not cause leaks, corrupted state or silent failures.
