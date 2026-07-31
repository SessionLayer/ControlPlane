package io.sessionlayer.controlplane.recording;

public record CustomerKeyMaterial(String keyRef, byte[] publicKey, String algorithm) {
}
