# SessionLayer Control Plane

The control and management plane of
[SessionLayer](https://github.com/SessionLayer), a self-hosted, API-first
Zero-Trust SSH access platform used from stock OpenSSH clients. It decides;
the [Gateway](https://github.com/SessionLayer/Gateway) enforces, and the
Control Plane never sees SSH session plaintext.

It holds authentication (OIDC, OTP, key pinning, machine identities),
authorization (data-plane RBAC, platform RBAC, JIT and break-glass, session
limits), the three SSH certificate authorities plus the internal mTLS CA,
fleet identity for Gateways and Agents, and the audit and recording metadata
stream.

## Stack

Spring Boot 4.1 / Java 25, fully reactive (WebFlux + R2DBC on Postgres; Flyway
migrates over JDBC at startup). The REST surface is generated from the frozen
OpenAPI contract in [`contracts/`](contracts/); the CP/Gateway/Agent plane is
gRPC over mTLS, generated from [`contracts/proto/`](contracts/proto/).

## Build and test

```bash
./mvnw -B -ntp verify     # codegen + compile + format/style checks + tests + ITs (needs Docker)
./scripts/gate.sh         # the full quality gate: adds contract lint + audit check
java -jar target/controlplane-*.jar
```

## Documentation

Installation, admin guides, the API reference, security model, and runbooks
live in the
[Documentation repository](https://github.com/SessionLayer/Documentation),
including the Postgres schema and its migration history in
`docs/reference/data-model.md`. Contract conventions specific to this repo are
in [`contracts/README.md`](contracts/README.md) and
[`contracts/VERSIONING.md`](contracts/VERSIONING.md).

## License

GPL-3.0-only. See [LICENSE](LICENSE).
