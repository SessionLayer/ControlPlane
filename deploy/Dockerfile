# syntax=docker/dockerfile:1
# SessionLayer Control Plane — production image, built from source.
#
# This is the from-source counterpart to
# Documentation/examples/quickstart/cp.Dockerfile, which installs the signed
# GitHub Release jar instead (cosign-verified against the release workflow's
# Sigstore identity). A from-source build has no release artifact to verify, so
# that step has no equivalent here; ship the quickstart path, not this one, when
# a signed release exists and source trust is not already established some other
# way (e.g. a reviewed, pinned commit).
#
# Three stages: Maven compiles the jar on the build platform, since the jar is
# architecture-neutral and cross-building it needs no emulation; jlink assembles
# a Java 25 runtime on the *target* platform, because it emits native launchers
# and shared libraries; the final image is distroless — no shell, no package
# manager, no compiler, and no JDK tooling.
#
# Bases are pinned by digest; the tag alongside is for readability, the same
# convention this project uses for GitHub Actions.
#
# The image does not itself drop privileges or apply seccomp/Landlock, unlike
# the Gateway: the JVM has no equivalent in-process hardening layer, so the
# container boundary that deploy/kubernetes/control-plane.yaml and
# deploy/systemd/ establish is the whole defence here, not a second layer on
# top of one.

# ---- jar ----
FROM --platform=$BUILDPLATFORM eclipse-temurin:25-jdk-noble@sha256:735baf2edc6cd6485240144a84fa4db142b9a6f47b4eb4080f31058d200f9813 AS jar
WORKDIR /src

# contracts/ is vendored (committed, pinned by contracts.lock) — codegen never
# reaches the network for the spec itself, only Maven Central for deps.
COPY . .

# The BuildKit cache mount persists ~/.m2 across builds without baking it into a
# layer. Tests are skipped: this stage has no Docker-in-Docker for the
# Testcontainers ITs, and `verify` runs separately in CI.
RUN --mount=type=cache,target=/root/.m2,sharing=locked \
    ./mvnw -B -ntp -DskipTests package \
 && cp target/controlplane-*.jar /controlplane.jar

# ---- image ----
# Adoptium's own JRE, copied onto a distroless base rather than linked with
# jlink. Temurin's images ship no jmods/ directory and are not linkable run-time
# images, so jlink cannot run in them at all; linking from another vendor's JDK
# would put a JVM in production that nothing was tested on, which is the drift
# the release's pinned build JDK exists to prevent. Measured, both 25.0.3+9:
# this JRE, the Maven stage above, and the JDK the released jar is compiled
# with are the same vendor and the same build.
#
# The module set is Adoptium's general-purpose one — not derived from static
# analysis of this application's bytecode, which is what matters, because Spring
# resolves modules reflectively and a jdeps-derived set can omit one an uncommon
# runtime path needs.
#
# `COPY --from` resolves per target platform, so arm64 needs no emulation.
FROM gcr.io/distroless/java-base-debian12:nonroot@sha256:a9930cad62d02853d7f3dede7281c4b916cbf74493c2d8d38564121aad92bf6c

ARG VERSION=0.0.0-dev
ARG REVISION=unknown
LABEL org.opencontainers.image.title="SessionLayer Control Plane" \
      org.opencontainers.image.description="API-first control and management plane for SessionLayer." \
      org.opencontainers.image.source="https://github.com/SessionLayer/ControlPlane" \
      org.opencontainers.image.licenses="GPL-3.0-only" \
      org.opencontainers.image.version="$VERSION" \
      org.opencontainers.image.revision="$REVISION"

COPY --from=eclipse-temurin:25-jre-noble@sha256:fbcf915c585659b30eb766ada4d6d7cfc9ec1040bf521e95bf61b10a25af73db /opt/java/openjdk /opt/java
COPY --from=jar /controlplane.jar /app/controlplane.jar

# The JVM needs a writable java.io.tmpdir whatever the root filesystem is
# (HotSpot's hsperfdata mappings, Netty unpacking its epoll .so) — mount a tmpfs
# here. Nothing else is written locally: CA keys and all other state live in
# Postgres, KEK-wrapped, and logging is stdout only.
VOLUME ["/tmp"]

# REST + actuator, and the mTLS gRPC plane — the port convention every
# deployment manifest in this project uses.
EXPOSE 8080 9443

# Numeric, so Kubernetes runAsNonRoot can enforce it without an /etc/passwd
# lookup. 65532 is what the distroless base declares and what the Gateway and
# Agent images already run as; a second convention for one component is one more
# number to keep in step across an image, a manifest and a chart. It owns
# nothing in the image, which is fine because every writable path is mounted in.
USER 65532:65532

# JAVA_TOOL_OPTIONS is deliberately not baked in: heap and GC belong to the
# deployment, which is what knows the memory limit.
ENTRYPOINT ["/opt/java/bin/java", "-jar", "/app/controlplane.jar"]
