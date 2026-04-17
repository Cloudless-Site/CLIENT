# Cloudless Architecture

## 🎸 Philosophy

Cloudless is a monolithic system written in C, designed with an intentionally minimal and old‑school approach.

One process.
No artificial layers.
No orchestration noise.

The system favors:
- direct control over abstraction
- predictable performance over flexibility theater
- simple primitives composed carefully instead of complex frameworks

This is a hard‑rock approach to software: raw, explicit, and engineered to be understood end‑to‑end by a single developer.

## 🧭 High Level Overview

Cloudless is composed of a single runtime that integrates:

- SSH control plane
- TCP/UDP dataplane
- SQLite embedded store
- internal routing and session models
- optional dashboard and external clients

There are no distributed subsystems.
All coordination happens inside the same process.

## 🔄 Runtime Flow

1. SSH connection is established
2. Command string is received (exec request)
3. Internal parser extracts verb and parameters
4. Control plane resolves:
   - service intent
   - pairing / authorization
   - routing configuration
5. Dataplane bindings are created
6. Traffic is handled in real time:
   - proxy (HTTP/HTTPS)
   - passthrough (raw TCP/UDP)
7. Lifecycle is managed internally:
   - session tracking
   - resource cleanup
   - state updates

All steps happen inside the same process with no external orchestration.

## 🎛️ Control Plane

Responsible for parsing SSH commands, mapping verbs, managing pairing and configuring runtime state.

## 🌊 Dataplane

Handles TCP/UDP sockets, bridging and proxying using an event-driven loop.

## 🗄️ Store

SQLite embedded storage for state, cache and configuration.

## ⚡ Performance & Optimization

- hash tables for fast lookup
- cache-friendly data structures
- single process → no IPC overhead
- epoll-based event loop
- minimal allocations on hot paths
- anti phishing bloom filter

## 📏 Design Constraints

- no unnecessary abstraction layers
- no hidden control flows
- no distributed coordination
- no dependency on external runtime services

## 📌 Summary

Monolithic, explicit, performance-oriented system designed for control and predictability.
