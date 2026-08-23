# OpenAPI contract

`openapi.yaml` is the **contract-first source of truth** for the SessionLayer
Control Plane REST surface. It is OpenAPI **3.1.0**.

## Contract-first, enforced

The spec is authored first; server and client code are **generated** from it,
and CI fails if the generated artifacts drift from the spec:

- **ControlPlane (Java):** `openapi-generator-maven-plugin` with the
  `spring` generator in reactive (`webflux`) mode produces API *interfaces* and
  *models*; controllers implement the interfaces. A drift between spec and code
  breaks the build.
- **Dashboard (TypeScript):** `openapi-typescript` produces types
  and `openapi-fetch` provides a typed client. `npm run generate:api` +
  `git diff --exit-code` is the CI drift check.

Error bodies are **RFC 9457** (`application/problem+json`, `ProblemDetails`),
with one documented exception: `POST /v1/bootstrap/claim`'s non-`200`
responses are a plain `{"status": "..."}` object, matching
`BootstrapService.ClaimOutcome` as actually implemented
(`ControlPlane/.../bootstrap/BootstrapController.java`) rather than the
platform's normal problem-document convention - this is a pre-existing
inconsistency in that one handler, called out here rather than silently
generalized away or silently left undocumented.

## Endpoints outside this contract (deliberate carve-outs)

Three `ControlPlane` routes are reachable but intentionally **not**
modeled here, so they never appear in the generated Java interfaces or the
TypeScript client:

- `GET /v1/auth/verify` and `GET /v1/auth/callback`
  (`web/AuthPagesController.java`) - server-rendered HTML pages (redirects
  and status pages) for the browser leg of the OIDC device/web-login flow.
  They return `text/html`, are navigated to directly by a browser (never
  called through `openapi-fetch`), and self-disable with a `404` page when
  OIDC is not configured (`!oidcProperties.isEnabled()`).
- `POST /v1/auth/backchannel-logout` (`web/BackchannelLogoutController.java`)
  - the OIDC Back-Channel Logout 1.0 IdP-to-RP webhook. Its request is
  `application/x-www-form-urlencoded` per that spec (not this contract's JSON
  convention), and its authentication is the signed `logout_token` JWT itself
  (verified via `idpJwtDecoder`), not a bearer/mTLS scheme this contract
  declares.

These are protocol-mandated, unauthenticated-by-bearer-scheme endpoints whose
shape is fixed by OIDC/OIDC-BCL, not by this API - modeling them here would
either misrepresent them (forcing a JSON schema onto an HTML/form endpoint)
or add generated client code nothing consumes. Both are rate-limited
(`RateLimiter`) against enumeration/abuse. If either ever gains a JSON
response body or becomes something the Dashboard calls programmatically, it
belongs in `openapi.yaml` at that point.

`POST /v1/bootstrap/claim` is **not** a carve-out - it is a genuine JSON
operation and is documented in `openapi.yaml` like any other.

## Security schemes (declared now, used later)

Three first-class schemes are declared so later operations reference them
without changing the contract shape:

- `oidcBearer` - OIDC/JWT bearer (the ID token is the auth proof).
- `clientCredentials` - OAuth 2.0 client-credentials for machine consumers.
- `mtls` - mutual-TLS client certificate (`type: mutualTLS`).

HTTP Basic is intentionally **absent** - it is not a first-class scheme on this
surface, and no operation may declare it.

### `mutualTLS` codegen note

`openapi-generator` 7.23 (the latest release) cannot model OpenAPI 3.1's
`type: mutualTLS` scheme: `DefaultCodegen.fromSecurity()` logs a non-fatal
`[ERROR] Unknown type mutualTLS ...` and emits no security metadata for it.
Because our generation uses `annotationLibrary=none` / `documentationProvider=none`,
security schemes are **documentation-only** and never appear in generated code -
so `mtls`-secured operations (e.g. `POST /v1/oauth2/token`, `POST /v1/auth/device`)
already generate compiling interfaces; mTLS is enforced by the Spring Security
client-cert filter, not by generated annotations. The contract keeps the correct
`type: mutualTLS`, and `.mvn/jvm.config` silences the redundant `DefaultCodegen`
logger so the build log stays clean. The contract-first drift gate is
**compile-based**, so silencing that logger cannot mask a real contract/model
drift - that always surfaces as a compile failure.

## Linting

Linted by Redocly CLI via `contracts/lint.sh` (config: `contracts/redocly.yaml`).
