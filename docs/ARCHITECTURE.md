# Cloudless Architecture

Cloudless is organized as a layered system with one canonical runtime model:

session -> service -> endpoint

A session represents an authenticated control connection.
A service represents one exposed local resource created by that session.
An endpoint is the public reachability derived from the service: HTTP or HTTPS domain, TCP port, or UDP port.

This separation is one of the core design strengths of the project:
- a session may own many services
- a service may change transport state without changing logical identity
- policy is enforced around the service model instead of being scattered only at socket level

## Design goals

Cloudless is built around a few stable goals:
- simple control semantics
- strict separation between control and traffic handling
- explicit service lifecycle management
- lightweight deployment and operation

The result is not just a tunnel helper.
It is closer to a compact service exposure platform with its own control plane, dataplane and persistence model.

## Layers

### Control Plane

Main responsibility: mutate runtime state.

Key pieces:
- SSH command handling in `src/control/`
- IPC command handling in `src/common/ipc_server.c`
- user and admin verbs in `cmd_user.c` and `cmd_admin.c`
- pair and tunnel lifecycle in `tunnel_req.c`

What it does:
- authenticate users
- create and destroy services
- register and verify domains
- apply ACL and policy decisions
- expose runtime state to dashboard and CLI

What it must not do:
- move packets in the hot path
- bypass the canonical service model

### Dataplane

Main responsibility: move traffic fast.

Key pieces:
- listeners in `src/dataplane/listeners/`
- TCP workers in `src/dataplane/tcp/`
- UDP workers in `src/dataplane/udp/`
- lightweight protocol sniffing in `src/dataplane/protocols/`

What it does:
- accept inbound traffic
- route packets and streams to live services
- keep runtime flow state
- avoid policy lookups in the hot path

What it must not do:
- talk to SQLite
- become a second control plane

The dataplane is intentionally isolated from the control plane so that traffic handling remains fast and predictable.

### Core Model

Main responsibility: hold runtime entities and contracts.

Key pieces:
- `src/core/`
- `include/core/`

What it does:
- represent sessions and services
- maintain ownership and references
- define state used by control plane and dataplane

### Store

Main responsibility: persistence.

Key pieces:
- `src/store/`

What it stores:
- users and plans
- domains and verification tokens
- ACL and policy tables
- dashboard and admin JSON views

Rule:
- the store is control-plane only
- the dataplane must stay database-free

### Dashboard

Main responsibility: external web interface.

Key pieces:
- `dashboard/`
- sleeve sidecar for IPC bridging

What it does:
- authenticate browser sessions
- call backend through IPC
- expose admin and user API
- stream runtime events over websocket

Rule:
- dashboard is an API client of the core, not a second backend

### Pair

Main responsibility: lightweight share and activation UX.

Key pieces:
- `src/core/pair.c`
- pair HTTP host handling in `src/common/http_static_proxy.c`

What it does:
- issue pair codes
- bind activators
- create short-lived pair sessions
- render pair landing and service views

Pair is not a bolt-on helper.
It is part of the same service lifecycle and uses the same runtime model as the rest of the system.

## Canonical flows

### Register -> Verify -> Tunnel

1. User calls `register@` through SSH.
2. Control plane validates arguments and writes pending data to store.
3. User calls `verify@ TOKEN`.
4. Control plane validates token and confirms ownership.
5. User opens `@up` or `@tunnel`.
6. Control plane creates service objects.
7. Dataplane exposes derived public reachability.

### Dashboard login

1. Browser loads dashboard.
2. User logs in with OTP or session cookie.
3. Dashboard talks to backend over sleeve IPC.
4. Backend returns user snapshot and permissions.
5. Dashboard enables user or admin views.

### Pair activation

1. Host exposes a service.
2. Control plane prints or renders a pair URL.
3. Remote user opens the pair URL.
4. Pair host activates identity and binds the activator IP.
5. Pair session is created.
6. Keepalive and disconnect manage lifecycle.

## Control substrate

The control plane is SSH-first.
Instead of inventing a large external protocol surface, Cloudless centers control semantics around SSH commands and validated IPC flows.
That gives the system a mature authenticated transport without turning the dataplane into an API framework.

Current product-facing verbs are centered on:
- `@up`
- `@tunnel`
- user commands like `register`, `verify`, `ls`, `sessions`, `get`, `put`, `protect`
- admin commands exposed consistently through CLI and IPC

## Layer contracts

- control plane mutates runtime state
- dataplane consumes runtime state
- store persists control-plane data
- dashboard reaches backend only through IPC
- pair is UX around the same canonical service model, not a parallel model

## Runtime invariants summary

- service is the central runtime entity
- public reachability is derived from service state
- worker-owned file descriptors must be closed by the owner worker
- dataplane remains policy-free in the hot path
- dashboard and CLI must expose the same backend semantics
- pair lifecycle must cleanup activator bindings and session state on failure

See `INVARIANTS.md` for the consolidated invariant set.

## Source-aligned notes

Cloudless is composed of two distinct layers:

1. Control plane:
   SSH commands such as register@, verify@, put@, get@, protect@, activate@, and admin commands.

2. Tunnel plane:
   Reverse SSH tunnels using up@ or tunnel@.

These layers are independent and follow different execution paths.

Tunnel mode is selected by the SSH username such as up or tunnel.
The public exposure is selected by the reverse bind token or public hostname, while backend metadata comes only from SSH command-line hints or backend probe. The public side and the backend side are different models and must not be mixed.

The current tunnel matrix is:
- up@:
  - public HTTPS gadget endpoint on Cloudless
  - raw tcp and udp slots may coexist
  - gadget hints are treated as truth
  - raw tcp and udp are never probed
  - gadget HTTP or HTTPS backend is probed only when hints are missing
- tunnel@:
  - raw tcp and udp
  - Cloudless HTTPS gadget endpoints
  - registered Cloudless hostnames in HTTPS proxy mode
  - full custom domains in passthrough mode
  - raw tcp and udp are never probed
  - Cloudless HTTPS endpoints probe backend HTTP or HTTPS only when hints are missing
  - full custom domains use TLS safety only and do not fall back to proxy mode

The validation flow now carries an explicit domain kind for tunnel decisions:
- gadget
- Cloudless hostname
- full custom domain
- raw

Initial route mode and probe policy are resolved from service type plus domain kind instead of being scattered across later mutation paths.

Human verification is not applied to admin commands.
It is limited to selected user-facing actions such as register, verify, release, script, and protect.

IPC communication between dashboard and backend includes protocol versioning and capability validation.
Mismatch results in explicit failure rather than silent degradation.

Connection teardown is defensive:
- half-close is delayed until buffers are drained
- connection map entries are invalidated before final close
- mailbox saturation triggers safe fallback paths

The system depends on external SSH client behavior such as Dropbear or OpenSSH.
Assumptions about command execution and output must be validated explicitly.

## Why the architecture works

Cloudless is strong because it separates mutation, forwarding, persistence and presentation.
That separation keeps the hot path small, the CLI expressive, the dashboard replaceable and the product extensible without turning the codebase into a haunted forest of cross-calls.
