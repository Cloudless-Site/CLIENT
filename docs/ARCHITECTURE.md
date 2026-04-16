# 🏗️ Cloudless Architecture

## 🎯 Purpose

This document describes the architectural model of Cloudless for a technical reader who wants to understand the system without reading the source code.

For the runtime flow see [How Cloudless Works](../00-overview/HOW-CLOUDLESS-WORKS.md).
For commands and real usage see the [User manual](../70-readmes/README-USER.md).

## 🚀 System Overview

Cloudless is an SSH-driven exposure engine.

Its job is to turn a tunnel request into a public network endpoint with deterministic behavior.

The architecture is built around a strict separation between:
- **Control plane** → receives intent
- **Resolution layer** → decides exposure behavior
- **Data plane** → executes traffic forwarding

This split is the core reason the system stays predictable.

## 🔌 Control Plane

Everything starts from an SSH connection.

The SSH username selects the operation model.
Examples include registration commands, inspection commands, and tunnel creation commands such as `up@` and `tunnel@`.

The control plane carries:
- the requested operation
- the public bind token
- the public port
- the backend address carried by the reverse tunnel request
- optional hints that refine HTTP or HTTPS backend behavior

### Architectural principle

SSH is not only authentication and transport.
It is also the control API.

This removes the need for a separate web API for the core workflow and keeps the external interface small.

## 🧠 Resolution Layer

After parsing, Cloudless resolves the request into a runtime binding.

Conceptually:

```text
input → interpretation → binding → exposure
```

The resolution layer decides:
- what kind of public endpoint is being requested
- whether the endpoint is proxy or passthrough
- how the public identity maps to the backend
- which protocol-specific behavior is legal for that endpoint

### Important invariant

The public side and the backend side are deliberately decoupled.

The public bind token defines the public identity and public behavior.
It does not blindly define backend semantics.

That separation prevents ambiguous routing and avoids a large class of accidental misconfigurations common in simpler tunnelers.

## 🌐 Domain and Endpoint Model

Cloudless distinguishes between several endpoint families.

### Cloudless HTTPS endpoints

These are endpoints published on Cloudless-managed names.
They are always exposed as HTTPS and always handled in proxy mode.

Architectural consequences:
- TLS is terminated by Cloudless
- the server presents the public certificate
- backend HTTP or HTTPS behavior is resolved using explicit hints or backend probing where applicable
- Host and SNI rewriting may be required to match backend expectations

### Raw transport endpoints

These are public `tcp` and `udp` slots.
They are transport-oriented and do not carry web semantics.

Architectural consequences:
- no HTTP interpretation
- no TLS termination by Cloudless
- exposure is tied to the requested public slot
- activation and access control can be handled separately from tunnel creation

### Full custom-domain endpoints

These are bring-your-own-domain endpoints.
They are distinct from Cloudless-managed HTTPS gadget names.

Architectural consequences:
- Cloudless acts as a passthrough system for the public connection path
- end-to-end TLS stays between the external client and the backend when the application protocol uses TLS
- Cloudless still enforces routing and safety constraints at setup time

## 🔁 Data Plane

The data plane handles live network traffic after the binding has been created.

Its responsibilities are:
- accept incoming traffic for the public endpoint
- match traffic to the runtime binding
- apply the selected mode
- forward the resulting stream or datagrams efficiently

### Proxy mode

Used for Cloudless HTTPS endpoints.

Cloudless terminates the public TLS session, interprets the public HTTP or HTTPS intent, and forwards traffic to the backend according to resolved backend behavior.

### Passthrough mode

Used for raw transport or full custom-domain cases where Cloudless must not terminate the application-layer security.

The system forwards traffic without converting the endpoint into a Cloudless-managed web proxy.

## ⚙️ Algorithms and Strategies

Cloudless is opinionated in the algorithms it uses.
The goal is not maximal flexibility at any cost, but stable behavior under real usage.

### 1. Deterministic resolution

The same tunnel request should resolve to the same exposure model.

Benefit:
- easier debugging
- fewer surprise transitions
- stable mental model for the user

### 2. Single-pass decision making

The control plane resolves the requested mode in one compact decision path instead of relying on long chains of deferred negotiation.

Benefit:
- lower setup latency
- fewer hidden state transitions
- reduced room for inconsistent intermediate states

### 3. Hint-first backend interpretation

When protocol hints are provided, they are treated as the most reliable source for backend web behavior.
Only when required does the system probe the backend.

Benefit:
- less guesswork
- better control for advanced users
- fewer accidental backend mismatches

### 4. Public-label-driven semantics

The public bind token is meaningful.
Reserved public labels such as `tcp`, `udp`, and `https*` are used to select legal exposure classes.

Benefit:
- compact user interface
- explicit routing semantics
- cleaner protocol separation

### 5. Runtime binding instead of static service inventory

Cloudless does not require a pre-populated service catalog before it can publish an endpoint.
The binding is created from the live request.

Benefit:
- minimal ceremony
- instant publication workflow
- reduced administrative overhead

## 🚄 Performance Strategy

Cloudless is designed to keep the fast path simple.

### Event-driven I/O

The system uses non-blocking sockets and event-driven scheduling.
This keeps a small number of workers capable of handling many simultaneous connections efficiently.

### Minimal buffering

Traffic forwarding is kept as direct as possible.
The design avoids unnecessary layers that would introduce additional copies, queues, or latency.

### Bounded state

The runtime model favors compact live state associated with active bindings and active traffic.
The system avoids turning the control plane into a large persistent orchestration layer for simple tunnel use cases.

### Early decision, cheap execution

Expensive decisions belong in the control and resolution path.
The live data path should mostly execute already-decided behavior.

## 🔐 Security Model

Cloudless keeps security decisions explicit.

### Control entry

SSH is the single control-plane entry point.
Authentication is therefore unified around SSH identities instead of parallel account systems.

### Clear proxy versus passthrough boundary

Cloudless-managed HTTPS endpoints are proxied.
Custom-domain passthrough endpoints are not silently converted into proxy mode.

### No hidden backend rewriting authority

Backend behavior is derived from the request model and explicit hints.
Cloudless does not treat the public side as permission to invent arbitrary backend semantics.

### Operational safety bias

Where there is ambiguity, the system prefers explicitness and constrained behavior over magical convenience.

## 🧩 Why the Architecture Matters

Many tunneling systems blur together:
- control commands
- endpoint naming
- backend identity
- transport mode
- TLS behavior

Cloudless keeps these concerns separate.
That is its architectural signature.

The result is a system that is:
- easier to reason about
- easier to audit conceptually
- more predictable in edge cases
- better suited to users who want exact exposure behavior

## 📌 Summary

Cloudless is an SSH-first architecture where user intent is resolved into a precise runtime binding and then executed by a lean data plane.

Its distinguishing characteristics are:
- explicit control-plane semantics
- deterministic exposure rules
- clear proxy and passthrough separation
- performance-oriented live traffic handling
- minimal external surface area
