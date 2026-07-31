# syntax=docker/dockerfile:1
# SessionLayer Control Plane — production image, built from source (Session
# Thirty-Seven).
#
# This is the from-source counterpart to
# Documentation/examples/quickstart/cp.Dockerfile, which installs the signed
# GitHub Release jar instead (cosign-verified against the release workflow's
# Sigstore identity). There is no release artifact to verify in a from-source
# build, so that verification step has no equivalent here; ship the quickstart
# path, not this one, when a signed release exists and source trust is not
# already established some other way (e.g. a reviewed, pinned commit).
#
# Two-stage build: a JDK stage compiles the jar with the repo's pinned
# toolchain (Java 25, the Maven Wrapper); the runtime stage carries only a JRE
# + the jar. Runs as non-root with a read-only root filesystem (see
# deploy/kubernetes/control-plane.yaml and deploy/systemd/ for the outer
# security context — this image does not itself drop privileges or apply
# seccomp/Landlock, unlike the Gateway: the JVM has no equivalent in-process
# hardening layer, so the container/OS boundary in those manifests is the
# whole defense here, not a second layer on top of one).
#
# Pin the base images by digest in your registry mirror for production (the
# tags below are for readability); the project pins GitHub Actions by SHA for
# the same supply-chain reason.

# ---- build stage ----
FROM eclipse-temurin:25-jdk-noble@sha256:3eb81ed94d8c1a34422f19f8188548bdf02cae69c91d0328afdbb7abed90f617 AS build
WORKDIR /src

# contracts/ is vendored (committed, pinned by contracts.lock) — codegen never
# reaches the network for the spec itself, only Maven Central for deps.
COPY . .

# The BuildKit cache mount persists ~/.m2 across builds without baking it into
# a layer (build once, reuse). Tests are skipped: this stage has no Docker-in-
# Docker for the Testcontainers ITs, and `verify` runs separately in CI/gate.sh.
RUN --mount=type=cache,target=/root/.m2,sharing=locked \
    ./mvnw -B -ntp -DskipTests package \
 && cp target/controlplane-*.jar /controlplane.jar

# ---- runtime stage ----
# Same base + digest as the quickstart's install-from-release path, so both
# on-ramps run the jar under an identically patched JRE. No distroless Java 25
# image exists yet to shrink this further (Gateway's distroless/cc has no Java
# counterpart); the trade-off is a full Ubuntu userland instead of "no shell at
# all" — mitigated by non-root + read-only-rootfs + dropped capabilities in the
# manifests, not by anything in this image.
FROM eclipse-temurin:25-jre@sha256:681c543d6f36c50f45e9b5226930a46203dcfa351d3670e9d0bdf0dabae53539 AS runtime

RUN groupadd --gid 10000 controlplane \
 && useradd --uid 10000 --gid controlplane --no-create-home --shell /usr/sbin/nologin controlplane

COPY --from=build /controlplane.jar /app/controlplane.jar

# The JVM needs a writable java.io.tmpdir regardless of rootfs (HotSpot's
# hsperfdata mapped files, among other things) — mount a tmpfs there (see
# deploy/kubernetes/control-plane.yaml's `tmp` volume / deploy/systemd's
# PrivateTmp=yes). Nothing else is written locally: CA keys and all other
# state live in Postgres (config.ca_config, KEK-wrapped), and no
# logging.file.* is configured (stdout only).
VOLUME ["/tmp"]

# REST + actuator (:8080) and the mTLS gRPC plane (:9443, matching the
# convention every deployment manifest in this project uses — see
# Documentation/docs/reference/ports.md's note on the 9090-vs-9443 default).
EXPOSE 8080 9443

USER controlplane:controlplane
ENTRYPOINT ["java", "-jar", "/app/controlplane.jar"]
