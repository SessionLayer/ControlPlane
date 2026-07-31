# Wire conformance vectors

Machine-checkable vectors that pin the **observable wire behaviour** of the
Agent↔Gateway (`agent-gateway-v1.md`) and Gateway↔Gateway relay
(`gateway-relay-v1.md`) protocols, so each consumer repo's **own** CI catches
cross-repo drift instead of relying on a human pass. The class of bug this
guards against is a wire endpoint advertising a version range it does not
actually implement — a defect invisible to either side's own suite because
each side is only ever wrong about the *other* one, so "both green" proves
nothing about interop.

Two files, two obligations:

| File | Pins | Consumed by |
|---|---|---|
| `negotiation-vectors.md` | version **negotiation** (advertised range + `resolve_common_version`) | each repo's version logic |
| `frames.json` | byte-exact **frame encodings** + decoder rejection behaviour | each repo's wire codec |

Both are **vendored** into the Gateway and Agent repos (like the protos) and run
in their `gate` job. No peer binary is needed — that is the point.

## `frames.json`

Golden frames, **generated from a known-correct codec, never hand-authored** (a
subtly wrong golden frame is a worse oracle than none). Framing is the frozen
`VER(1) | TYPE(1) | LENGTH(u32 BE) | PAYLOAD`; payloads are the prost
serialization of the message named in the catalogue (§4), except `STREAM_DATA`
whose payload is raw opaque bytes. The prost encoding is deterministic over the
same frozen proto both repos generate from, so the bytes are authoritative; the
generator additionally decodes every frame it emits (self-check) and asserts a
hand-computable anchor (`Ping{nonce=42}` → `011000000002082a`).

Regenerate **only when the contract changes**:

```
cd framegen && cargo run          # rewrites frames.json; commit it
```

`framegen/` is a self-contained dev tool (its own `target/`, prost over the vendored
protos) so regenerating never touches a consumer repo's build.

### Regenerating the golden

`framegen` is a manual dev tool and does not run in CI, so **nothing detects a
stale `frames.json`**: if a proto changes and the golden is not regenerated, both
Rust repos vendor the old bytes and both conformance suites pass against it.
Regenerate whenever you change a proto in this directory's inputs, and review the
`frames.json` diff in the same commit as the proto change.

### What each repo asserts (portable, no field-construction glue)

For every entry in `frames`:

1. **Decode** `frame_hex` with the repo's codec → succeeds, and the decoded
   `ver` / `type` / `payload` equal `ver` / `type` / `payload_hex`.
2. **Re-frame** `encode(ver, type, payload)` → equals `frame_hex` byte-for-byte.

Together these pin the framing *and* the exact payload bytes both sides must
agree on. Neither repo reconstructs a message from its fields: `message` (the
fully-qualified proto name) and `fields` (a human description of the encoded
values) are **annotations for the reader**, not machine inputs. A consumer
re-encodes the golden *payload* byte-for-byte (step 2) but does not re-derive it
from scratch — the payload's encoding *correctness* is delegated to the vendored
proto both repos generate from and pinned upstream by the golden-integrity check
above.

For every entry in `decode_negatives`: **decode** `hex` → the codec rejects it
with the error named by `expect` (mapping to `agent/wire.rs::FrameError`:
`Short` / `LengthMismatch` / `TooLarge` / `UnknownType` / `BadVersion`). The
oversized case is rejected **at the length header, without buffering the body**.

### Role-appropriate obligations (parties vs partial parties)

"Decode every golden frame" is the right obligation only for a consumer that is a
**party to every protocol** sharing the registry — the **Gateway**, which is both
the Agent↔Gateway server and the Gateway↔Gateway relay server, so it legitimately
decodes all 16 frames including the RELAY types (`0x24`–`0x26`).

A **partial-party** consumer — the **Agent** is not a party to the
Gateway↔Gateway relay — MUST NOT decode a protocol it does not speak. Its portable
obligation is instead:

- **byte-pin** the §2 framing + payload for *all* frames (re-encode the types it
  owns byte-exact; assert the frozen layout formula for the rest), so the shared
  bytes stay the oracle and the type-number registry is pinned — `0x24`–`0x26`
  cannot be reused for one of its own types without this test failing;
- **accept** every frame it may legitimately receive;
- **refuse** every frame it must not — its own *outbound* types with an
  illegal-direction error, and any *non-party* / reserved type (RELAY) with an
  unknown-type error.

Refusing a non-party type as *unknown* (rather than carrying it in the codec's
registry as known-but-unhandled) is the stronger posture: the consumer never
silently accepts a frame from a protocol it does not speak, and the shared
numbering is still pinned. The Agent's `tests/wire_conformance.rs` is the
reference partial-party adaptation; the shared golden bytes remain the single
oracle in every repo's CI regardless of role.

A reference consumer test (portable Rust, drop into each repo's `tests/`) lives
in [`consumer-test.rs.txt`](./consumer-test.rs.txt).

## How the cross-repo wire tests run (the two tiers)

The wire is proven at two tiers, split so the cheap deterministic checks live in
every repo's own CI and the expensive real-binary run stays out of it:

**Tier 1 — per-repo conformance (this directory).** `frames.json` +
`negotiation-vectors.md` are vendored into the Gateway and Agent repos (via each
`scripts/vendor-contracts.sh`, alongside the protos) and run in each repo's `gate`
job as `tests/wire_conformance.rs` (from `consumer-test.rs.txt`). No peer binary,
no network, no Docker — a repo catches its **own** wire/codec drift before it
ever reaches a cross-repo run. Same golden bytes on both sides is the
mechanically-enforced contract.

**Tier 2 — cross-repo real-binary E2E (SessionLayer/Gateway).** A per-repo suite
runs against a mock Control Plane, which cannot surface a genuine cross-repo
mismatch. The Gateway therefore carries `tests/fullstack/run.sh`, driven by its
`.github/workflows/fullstack-e2e.yml`: a real Control Plane jar + a real Gateway
binary + a real Agent binary + a real Debian node + a stock ssh client, checked
out from the sibling repositories and driven through a real `Authorize`
decision. It is expensive, so it runs on dispatch and nightly on `main` rather
than on every push.
