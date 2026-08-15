# SessionLayer — Canonical Cross-Repo Contracts

This directory is the **single source of truth** for every contract that crosses
a component boundary in SessionLayer. It is **contract-first**: the contracts
here are authored and frozen *before* any consumer generates code, and every
repo derives its types from these files — no repo hand-writes a divergent copy.

It lives in the `SessionLayer/Contracts` repo, independently versioned and
tagged, and is vendored by every consumer — including `ControlPlane`.

## Layout

```
contracts/
├── openapi/                 # REST contract (OpenAPI 3.1)
│   ├── openapi.yaml         #   the Control Plane's full REST surface
│   └── README.md            #   how the spec is consumed by codegen, and its carve-outs
├── proto/                   # gRPC contracts (protobuf, buf-managed)
│   ├── buf.yaml             #   buf module: lint + breaking-change rules
│   ├── buf.gen.yaml         #   canonical (reference) codegen plugin set
│   ├── sessionlayer/controlplane/v1/   #   CP <-> Gateway/Agent plane
│   ├── sessionlayer/agent/v1/          #   Agent <-> Gateway payloads
│   └── sessionlayer/gateway/v1/        #   Gateway <-> Gateway coordination
├── wire/
│   ├── agent-gateway-v1.md  # Agent <-> Gateway wire-protocol SPECIFICATION
│   ├── gateway-relay-v1.md  # Gateway <-> Gateway peer-relay SPECIFICATION
│   └── conformance/         # golden frames + provenance, and the generator
├── redocly.yaml             # OpenAPI linter config (Redocly CLI)
├── lint.sh                  # single entrypoint: buf lint + buf breaking + redocly lint
├── VERSIONING.md            # the N-1 compatibility policy
└── README.md                # this file
```

## Who consumes what

| Repo | Consumes | How it generates |
|---|---|---|
| **ControlPlane** (Java) | `proto/` (server), `openapi/` (server interfaces) | `protobuf-maven-plugin` + `protoc-gen-grpc-java`; `openapi-generator-maven-plugin` (spring/webflux) — build fails on drift |
| **Gateway** (Rust) | `proto/` (client + the agent/gateway payloads) | `tonic-prost-build` in `build.rs` against a vendored copy of `proto/` |
| **Agent** (Rust) | `proto/` (`common`/`agent` types, the wire payloads), `wire/` (spec) | `tonic-prost-build` in `build.rs` |
| **Dashboard** (TS) | `openapi/` | `openapi-typescript` + `openapi-fetch`; CI fails if the checked-in client drifts |

Each consumer vendors a committed copy rather than referencing this repo by
path: every repo must build standalone, and a committed vendored copy keeps
builds reproducible and reviewable. The vendored copy is pinned by that repo's
`contracts.lock` (tag + resolved commit SHA), and its CI re-fetches the pinned
tag to prove the copy has not drifted. The authoritative copy is always the one
here.

## Linting (CI merge gate)

```bash
contracts/lint.sh      # buf lint + buf breaking + redocly lint
```

Requires `buf` and a Node/`npx` toolchain on PATH. This script is the Contracts
repo's required check and is also wired into the ControlPlane gate against
its vendored copy.

## Freeze discipline

The contract is **frozen** for consumers: a consumer never edits its vendored
copy. A contract change is authored here, goes through the versioning procedure
in `VERSIONING.md`, is released under a new tag, and is then adopted by each
consumer as a reviewed `contracts.lock` bump plus a re-vendor. Breaking changes
are mechanically caught by `buf breaking`.
