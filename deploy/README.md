# Deploying the Control Plane

`Dockerfile`, `kubernetes/`, and `systemd/` here are the release artifacts. For
how to use them, see `docs/installation/control-plane.md` in the
[Documentation](https://github.com/SessionLayer/Documentation) repo.

## The image

The release workflow builds `ghcr.io/sessionlayer/controlplane:<tag>` from
`Dockerfile` on every `v*` tag, for `linux/amd64` and `linux/arm64`. Each push
carries an SPDX SBOM and SLSA provenance as in-toto attestations on the index,
and a keyless Sigstore signature over the index and both platform manifests. No
`:latest` tag is published - pin a tag, or a digest.

The runtime is a Java 25 runtime on a distroless base: no shell, no package
manager, no JDK tooling. It runs as uid 65532 and writes to one path, `/tmp`,
for the JVM's `java.io.tmpdir`. Mount a tmpfs or an `emptyDir` there and the
root filesystem can be read-only, as `kubernetes/control-plane.yaml` does.

Build it yourself from the repo root:

```
docker build -f deploy/Dockerfile -t sessionlayer/controlplane:dev .
```
