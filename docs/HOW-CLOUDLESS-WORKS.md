# 📖 How Cloudless Works

## 🎯 Purpose

This document explains the runtime behavior of Cloudless.
It focuses on what happens from the moment a user opens an SSH session to the moment traffic starts flowing.

For the broader design see [Architecture](../10-architecture/ARCHITECTURE.md).
For commands and examples see the [User manual](../70-readmes/README-USER.md).

## 🔌 Entry Point

Everything starts from an SSH connection.

Two broad families of actions exist:
- control-plane actions such as registration, inspection, verification, activation, and dashboard access
- tunnel-plane actions such as `up@` and `tunnel@`

For tunnel creation, the incoming request provides:
- a command verb
- a public bind token
- a public port
- a backend address through the reverse tunnel request
- optional protocol hints

## ⚙️ Resolution Flow

Cloudless turns the request into a live binding through a compact runtime flow.

```text
parse → classify → resolve → activate
```

### Step 1 — Parse

Cloudless extracts:
- the requested verb
- the public bind token
- the public port
- the backend destination carried by the reverse tunnel
- any hint affecting backend web behavior

At this stage the system has not yet decided whether the request is raw transport, HTTPS proxy, or custom-domain passthrough.

### Step 2 — Classify

The public bind token and command verb determine the legal exposure family.

Examples:
- empty public token with `up@` means generated Cloudless HTTPS gadget publishing
- `https`, `https1`, `https2`, and similar labels belong to the Cloudless HTTPS family
- `tcp` and `udp` are reserved raw transport labels
- a hostname containing dots may represent either a Cloudless-managed hostname or a full custom domain depending on the request

This step is crucial because Cloudless does not want public endpoint type to be ambiguous.

### Step 3 — Resolve backend behavior

Once the public exposure family is known, Cloudless decides how the backend should be reached.

For Cloudless HTTPS endpoints:
- the public side remains HTTPS
- the backend may be HTTP or HTTPS
- explicit command-line hints are preferred when present
- backend probing is used only where required
- Host and SNI rewriting may be applied when necessary to match backend expectations

For raw transport:
- the system keeps transport semantics raw
- no web interpretation is introduced

For full custom domains:
- the system keeps the public connection in passthrough mode
- Cloudless does not turn the endpoint into a Cloudless HTTPS proxy

### Step 4 — Activate the binding

After resolution, Cloudless creates the live runtime mapping.

At that point:
- the public endpoint exists
- the requested mode is fixed for that binding
- the data plane can begin accepting traffic

Some endpoint families become immediately usable.
Others still require consumer-side activation or equivalent access authorization before external traffic is admitted.

## 🌐 Endpoint Behavior in Practice

### Cloudless HTTPS gadget or Cloudless HTTPS label

Runtime behavior:
- public endpoint is HTTPS
- Cloudless terminates public TLS
- Cloudless forwards to the backend in proxy mode
- backend web behavior is selected using hints or backend probe

Typical result:
- fast web publishing with a stable public model
- no need for the user to expose raw TLS directly on the public side

### Raw TCP or raw UDP slot

Runtime behavior:
- public endpoint is a transport slot
- Cloudless does not reinterpret it as a web endpoint
- consumer access can be gated separately from publication

Typical result:
- SSH, databases, WireGuard-style transport, custom protocols, or UDP applications can be published without forcing web semantics onto them

### Full custom-domain passthrough

Runtime behavior:
- the endpoint remains tied to the user's own domain
- Cloudless routes the traffic but does not terminate the application-layer TLS for that endpoint family

Typical result:
- the user retains end-to-end TLS ownership for the custom domain path

## 🔁 Incoming Traffic Path

Once a binding is live, the runtime path is simple:

1. external traffic arrives at the public endpoint
2. Cloudless matches the endpoint to the active binding
3. the data plane applies the resolved mode
4. traffic is forwarded to the backend

There is no second round of high-level negotiation on the fast path.
The heavy decision was already made during setup.

## ⚡ Runtime Properties

### Deterministic

Given the same public request model and the same hints, Cloudless aims to produce the same exposure behavior.

### Immediate

The binding is derived from the live request itself.
Cloudless does not require a long provisioning workflow before basic tunnel use.

### Explicit

Cloudless prefers visible rules over hidden convenience.
This is why public labels, command verbs, and hints all matter.

### Cheap on the fast path

Classification and resolution happen before live traffic forwarding.
Once traffic is flowing, the data plane mostly executes already-decided behavior.

## 🚄 Why This Flow Is Fast

Cloudless keeps the runtime path short by using a few practical strategies:
- compact parsing of SSH intent
- early classification of endpoint type
- hint-first backend interpretation
- event-driven traffic handling after activation

This reduces both setup ambiguity and per-connection overhead.

## 📌 Summary

Cloudless works by converting SSH intent into a concrete public exposure model, resolving the correct runtime behavior, and then letting a lean data plane execute that decision.

In short:
- SSH expresses intent
- Cloudless resolves the endpoint class
- the binding becomes live
- traffic follows the already-chosen rules
