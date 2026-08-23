# syntax=docker/dockerfile:1
# SessionLayer Control Plane - production image, built from source.
#
# This is the from-source counterpart to
# Documentation/examples/quickstart/cp.Dockerfile, which installs the signed
# GitHub Release jar instead (cosign-verified against the release workflow's
# Sigstore identity). A from-source build has no release artifact to verify, so
# that step has no equivalent here; ship the quickstart path, not this one, when
# a signed release exists and source trust is not already established some other
# way (e.g. a reviewed, pinned commit).
#
# Two stages: Maven compiles the jar on the build platform, since the jar is
# architecture-neutral and cross-building it needs no emulation; the runtime is
# copied per target platform out of the Corretto image, so nothing executes for a
# foreign architecture and the build needs no emulation either. The final image is
# distroless - no shell, no package manager, no compiler, and no JDK tooling.
#
# Bases are pinned by digest; the tag alongside is for readability, the same
# convention this project uses for GitHub Actions.
#
# The image does not itself drop privileges or apply seccomp/Landlock, unlike
# the Gateway: the JVM has no equivalent in-process hardening layer, so the
# container boundary that deploy/kubernetes/control-plane.yaml and
# deploy/systemd/ establish is the whole defence here, not a second layer on
# top of one.

FROM --platform=$BUILDPLATFORM amazoncorretto:25@sha256:10a3c794ac57ecfc386938283fba9da351c5f0bda3a155482a1193b9806f1854 AS jar
WORKDIR /src

# The Maven wrapper unpacks the distribution itself and has no Java fallback for
# that step, so it needs an extractor the base image does not carry. Build stage
# only; nothing here reaches the final image.
RUN dnf install -y --setopt=install_weak_deps=False tar gzip && dnf clean all

COPY . .

RUN --mount=type=cache,target=/root/.m2,sharing=locked \
    ./mvnw -B -ntp -DskipTests package \
 && cp target/controlplane-*.jar /controlplane.jar

# ---- image ----
# The runtime is Corretto's own, copied onto a distroless base. It is deliberately
# not a jlink-derived set: `COPY --from` resolves per target platform and executes
# nothing, whereas jlink would have to RUN on the target platform and so would drag
# QEMU into every build. It is also the general-purpose module set rather than one
# derived from static analysis of this application's bytecode, because Spring
# resolves modules reflectively and a jdeps-derived set can omit one an uncommon
# runtime path needs.
#
# Same vendor and same build as the Maven stage above and as the JDK the released
# jar is compiled with (Corretto 25.0.4.8.1) - a JVM in production that nothing was
# tested on is exactly the drift the release's pinned build JDK exists to prevent.
#
# `bin/` is not copied wholesale: only the launcher, so the "no JDK tooling"
# property above holds literally rather than approximately.
FROM gcr.io/distroless/java-base-debian12:nonroot@sha256:a9930cad62d02853d7f3dede7281c4b916cbf74493c2d8d38564121aad92bf6c

ARG VERSION=0.0.0-dev
ARG REVISION=unknown
LABEL org.opencontainers.image.title="SessionLayer Control Plane" \
      org.opencontainers.image.description="API-first control and management plane for SessionLayer." \
      org.opencontainers.image.source="https://github.com/SessionLayer/ControlPlane" \
      org.opencontainers.image.licenses="GPL-3.0-only" \
      org.opencontainers.image.version="$VERSION" \
      org.opencontainers.image.revision="$REVISION"

COPY --from=amazoncorretto:25-headless@sha256:770e291fe5d1bc20254c49489a6762095fa93937c11fa5e7408c3a3e4e04931e /usr/lib/jvm/java-25-amazon-corretto/lib      /opt/java/lib
COPY --from=amazoncorretto:25-headless@sha256:770e291fe5d1bc20254c49489a6762095fa93937c11fa5e7408c3a3e4e04931e /usr/lib/jvm/java-25-amazon-corretto/conf     /opt/java/conf
COPY --from=amazoncorretto:25-headless@sha256:770e291fe5d1bc20254c49489a6762095fa93937c11fa5e7408c3a3e4e04931e /usr/lib/jvm/java-25-amazon-corretto/release  /opt/java/release
COPY --from=amazoncorretto:25-headless@sha256:770e291fe5d1bc20254c49489a6762095fa93937c11fa5e7408c3a3e4e04931e /usr/lib/jvm/java-25-amazon-corretto/legal    /opt/java/legal
COPY --from=amazoncorretto:25-headless@sha256:770e291fe5d1bc20254c49489a6762095fa93937c11fa5e7408c3a3e4e04931e /usr/lib/jvm/java-25-amazon-corretto/bin/java  /opt/java/bin/java
COPY --from=jar /controlplane.jar /app/controlplane.jar

# The JVM needs a writable java.io.tmpdir whatever the root filesystem is
# (HotSpot's hsperfdata mappings, Netty unpacking its epoll .so) - mount a tmpfs
# here. Nothing else is written locally: CA keys and all other state live in
# Postgres, KEK-wrapped, and logging is stdout only.
VOLUME ["/tmp"]

EXPOSE 8080 9443

# Numeric, so Kubernetes runAsNonRoot can enforce it without an /etc/passwd
# lookup. 65532 is what the distroless base declares and what the Gateway and
# Agent images already run as; a second convention for one component is one more
# number to keep in step across an image, a manifest and a chart. It owns
# nothing in the image, which is fine because every writable path is mounted in.
USER 65532:65532

ENTRYPOINT ["/opt/java/bin/java", "-jar", "/app/controlplane.jar"]
