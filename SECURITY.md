# Security policy

Report a vulnerability through GitHub's private vulnerability reporting: the
**Security** tab above, then **Report a vulnerability**. That opens a thread
only you and the maintainers can read. Do not open a public issue, pull
request, or discussion for a security finding.

[SessionLayer's vulnerability disclosure policy](https://github.com/SessionLayer/Documentation/blob/main/docs/security/vulnerability-disclosure.md)
is the single authority for every repository in this organization: what to
include in a report, full scope, embargo and credit, and how to verify that
the release you installed is the build the advisory named. Read it before
reporting.

## Scope in this repository

The SessionLayer Control Plane holds policy, identity, the certificate
authorities, and the audit trail. It never sees SSH session plaintext; a
finding that puts plaintext here breaks that invariant and should say so
explicitly.

In scope: authentication and authorization, the certificate authorities and
their signing paths, session limits and leases, the audit hash chain and its
WORM interaction, the REST API, platform RBAC, and `release.yml`.

Not accepted here: the built-in dev KEK and
`sessionlayer.ca.local.allow-dev-kek=true`. The default is `false` and the
Control Plane refuses to start on a local CA using the dev KEK without that
explicit override, so production is already fail-closed against it. The policy
lists the rest of the out-of-scope set, including test fixtures, volumetric
denial-of-service testing, anything starting from a credential the threat
model already assumes lost, and accepted risks already documented in the trust
model.

## Response targets

The [disclosure policy](https://github.com/SessionLayer/Documentation/blob/main/docs/security/vulnerability-disclosure.md)
carries the one timeline this organization keeps, from acknowledgement through
triage, fix and embargo, and it covers every repository including this one.
Advisories credit you unless you ask to stay anonymous, and request a CVE for
findings rated moderate or above. There is no bug bounty.
