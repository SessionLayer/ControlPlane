# sessionlayer-controlplane

Deploys the SessionLayer Control Plane as a Deployment, Service, ConfigMap,
ServiceAccount, PodDisruptionBudget and NetworkPolicy. The chart is a
translation of `deploy/kubernetes/control-plane.yaml` and
`deploy/kubernetes/networkpolicy.yaml`; those manifests remain the reference
for a deployment that does not use Helm.

The chart creates no Secret. Every credential is referenced by the name of a
Secret you create out of band, and rendering fails with a message naming the
value when a reference is missing.

## Install

Create the Secret first. `deploy/kubernetes/secret.example.yaml` lists the keys
and how to generate each value.

```bash
kubectl -n sessionlayer apply -f my-controlplane-secrets.yaml

helm install cp deploy/helm/sessionlayer-controlplane \
  --namespace sessionlayer --create-namespace \
  --set secrets.existingSecret=sessionlayer-controlplane-secrets \
  --set recording.worm.endpoint=https://worm.example.com \
  --set oidc.issuer=https://idp.example.com \
  --set oidc.clientId=sessionlayer-controlplane \
  --set oidc.redirectUri=https://cp.example.com/v1/auth/callback \
  --set image.digest=sha256:<the digest you verified>
```

Replace `sessionlayer` with your namespace, the `worm` and `idp` hosts with
your object store and identity provider, and `<the digest you verified>` with
the digest `cosign verify` reported for `ghcr.io/sessionlayer/controlplane`.

`ci/production-values.yaml` is a complete values file with every optional path
switched on, kept as the file the chart is linted and schema-checked against.

## Migrations and rolling updates

The chart runs no migration initContainer and no migration Job, and that is
deliberate. Flyway runs synchronously during Spring context refresh, before the
web server's lifecycle starts and well before any `ApplicationRunner`. Spring
Boot does not flip readiness to `ACCEPTING_TRAFFIC` until every
`ApplicationRunner` has returned, which is itself after Flyway. So "migrate on
boot, gate traffic on `/actuator/health/readiness`" falls out of Boot's own
startup sequencing, and `probes.readiness` is what enforces it.

Two replicas can therefore run Flyway at once during a rolling update. That is
safe rather than merely tolerated: Flyway's Postgres support takes a
database-level lock before applying migrations, so the second pod blocks until
the first finishes, then finds nothing pending and does nothing. The generous
`probes.startup.failureThreshold` of 60 exists so that lock wait, plus the two
bounded bootstrap runners, never trips a restart mid-lock-wait. Lowering it is
how a slow first migration becomes a restart loop.

What none of this solves: forward compatibility of the schema across the two
image versions that coexist during a rollout is an application concern
(expand-and-contract migrations), not a deployment one.

## Values

### Image

| Key | Default | Notes |
|---|---|---|
| `image.repository` | `ghcr.io/sessionlayer/controlplane` | |
| `image.tag` | `""` | Empty resolves to the chart's `appVersion`. |
| `image.digest` | `""` | Wins over `tag`. Pin this in production. |
| `image.pullPolicy` | `IfNotPresent` | |
| `imagePullSecrets` | `[]` | |

### Secrets

| Key | Default | Notes |
|---|---|---|
| `secrets.existingSecret` | `""` | Name of the Secret projected into the container with `envFrom`. Rendering fails without it. |

The Secret carries `SPRING_FLYWAY_PASSWORD`,
`SPRING_FLYWAY_PLACEHOLDERS_CPRUNTIMEPASSWORD`, `SPRING_R2DBC_PASSWORD`,
`SESSIONLAYER_CA_LOCAL_KEK_BASE64`, `SESSIONLAYER_OIDC_CLIENT_SECRET`,
`SESSIONLAYER_OIDC_STATE_HMAC_KEY`,
`SESSIONLAYER_RECORDING_WORM_ACCESS_KEY` and
`SESSIONLAYER_RECORDING_WORM_SECRET_KEY`.

> **Warning:** the Control Plane refuses to start when
> `SESSIONLAYER_CA_LOCAL_KEK_BASE64` is absent unless
> `SESSIONLAYER_CA_LOCAL_ALLOW_DEV_KEK` is `true`, which wraps certificate
> authority private keys under a public constant. This chart exposes no value
> for that flag, so enabling it in production takes a deliberate `extraEnv`
> entry rather than a forgotten default.

### Database

| Key | Default |
|---|---|
| `database.r2dbcUrl` | `r2dbc:postgresql://postgres.sessionlayer.svc:5432/sessionlayer` |
| `database.r2dbcUsername` | `cp_runtime` |
| `database.flywayUrl` | `jdbc:postgresql://postgres.sessionlayer.svc:5432/sessionlayer` |
| `database.flywayUsername` | `sessionlayer` |

Two roles on purpose: Flyway migrates as the owner, the request path runs as
the restricted `cp_runtime` role.

### Network identity

| Key | Default | Notes |
|---|---|---|
| `mtls.port` | `9443` | The gRPC plane Gateways and Agents dial. The application's own default is `9090`; every SessionLayer deployment example uses `9443`, and the Gateway and Agent endpoint defaults match. |
| `mtls.extraHostnames` | `[]` | Extra SANs for the certificate the process mints at runtime. In-cluster service names are added for you. |
| `service.name` | `controlplane` | Fixed rather than release-derived, because the Gateway's `cp_mtls_endpoint` and the Agent's `--cp-endpoint` default to `controlplane.<namespace>.svc`. One release per namespace follows from this. |
| `service.type` | `ClusterIP` | |
| `service.ports.rest` | `8080` | |
| `service.ports.mtlsGrpc` | `9443` | |

### Recording and login

| Key | Default | Notes |
|---|---|---|
| `recording.worm.endpoint` | `""` | Required. The application ships a development default pointing at a local MinIO with a well-known credential, so an unset endpoint is a real hazard rather than an inconvenience. |
| `recording.worm.region` | `us-east-1` | |
| `recording.worm.bucket` | `sessionlayer-recordings` | |
| `recording.worm.pathStyleAccess` | `false` | |
| `oidc.enabled` | `true` | Set to `false` for an OTP, pins or machine-identity-only deployment. |
| `oidc.issuer` | `""` | Required when `oidc.enabled`. |
| `oidc.clientId` | `""` | Required when `oidc.enabled`. |
| `oidc.redirectUri` | `""` | Required when `oidc.enabled`. |

### Runtime

| Key | Default | Notes |
|---|---|---|
| `replicaCount` | `2` | |
| `resources.requests` | `250m` / `512Mi` | |
| `resources.limits` | `1` / `1Gi` | |
| `java.toolOptions` | `-XX:MaxRAMPercentage=75.0` | The JVM's default of 25% undersizes the heap against the memory limit for a WebFlux, gRPC and R2DBC workload. |
| `terminationGracePeriodSeconds` | `30` | No long-lived byte stream terminates here. |
| `updateStrategy` | `maxSurge: 1`, `maxUnavailable: 0` | Keeps a replica serving across the Flyway lock wait described above. |
| `tmpVolume` | `Memory`, `256Mi` | Netty unpacks its native epoll transport into `/tmp` at startup. If it cannot, it falls back to NIO with a log warning rather than failing. |
| `podDisruptionBudget.enabled` | `true` | |
| `podDisruptionBudget.minAvailable` | `1` | Rendering fails when this is not below `replicaCount`, because such a budget refuses every voluntary eviction and hangs a node drain. |

### Probes

| Key | Default | Notes |
|---|---|---|
| `probes.readiness.periodSeconds` | `5` | `/actuator/health/readiness`, which reflects Boot's `ReadinessState`. |
| `probes.liveness.periodSeconds` | `15` | `/actuator/health/liveness`, which reflects `LivenessState` only and never a downstream dependency. A slow Postgres surfaces as a failed request, not a restart storm. |
| `probes.startup.periodSeconds` | `5` | |
| `probes.startup.failureThreshold` | `60` | Five minutes. See Migrations above. |

### Security context

| Key | Default |
|---|---|
| `podSecurityContext` | `runAsNonRoot: true`, uid/gid/fsGroup `65532`, `seccompProfile: RuntimeDefault` |
| `containerSecurityContext` | `allowPrivilegeEscalation: false`, `readOnlyRootFilesystem: true`, `capabilities.drop: [ALL]` |
| `serviceAccount.automountServiceAccountToken` | `false` |

The Control Plane never calls the Kubernetes API, so a projected token in the
pod is credential surface with no purpose.

### NetworkPolicy

| Key | Default | Notes |
|---|---|---|
| `networkPolicy.enabled` | `true` | Default-deny both directions. Needs a CNI that enforces NetworkPolicy. |
| `networkPolicy.wormCidrs` | `[]` | Egress to the object store. |
| `networkPolicy.oidcCidrs` | `[]` | Egress to your identity provider. |
| `networkPolicy.extraGrpcIngressCidrs` | `[]` | Agents on fleet nodes outside the cluster reach `mtls.port` from an address no pod selector can express. |
| `networkPolicy.postgresPodSelector` | `app.kubernetes.io/name: postgresql` | Replace with an `extraEgress` `ipBlock` for a managed database. |
| `networkPolicy.gatewayPodSelector` | `app.kubernetes.io/name: sessionlayer-gateway` | Matches the label the Gateway chart applies. |
| `networkPolicy.agentPodSelector` | `app.kubernetes.io/name: sessionlayer-agent` | Matches the label the Agent chart applies. |
| `networkPolicy.otelPodSelector` | `{}` | Empty omits the trace-export egress rule. |

The CIDR lists start empty. A placeholder range permits egress to hosts that
are not your object store or your identity provider, which is worse than no
rule at all, so those rules are absent until you name the range. The install
notes print what is currently denied. NetworkPolicy has no DNS-based match in
the core API; for a public S3 or a SaaS identity provider, use your CNI's FQDN
policy support or a VPC-level control instead.

### Scheduling and extension

`podAnnotations`, `podLabels`, `nodeSelector`, `tolerations`, `affinity`,
`topologySpreadConstraints`, `priorityClassName`, `extraEnv`, `extraEnvFrom`,
`extraVolumes` and `extraVolumeMounts` pass through unchanged.

## What this chart is not

It is validated statically: `helm lint`, `helm template`, `values.schema.json`
and `kubeconform -strict` against the Kubernetes schemas. It has not been
installed into a live cluster as part of this repository's testing.

## See also

- `deploy/kubernetes/` for the plain manifests this chart translates
- `deploy/kubernetes/secret.example.yaml` for the credential key list
- [Control Plane installation](https://github.com/SessionLayer/Documentation/blob/main/docs/installation/control-plane.md)
