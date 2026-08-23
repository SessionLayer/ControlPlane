package io.sessionlayer.controlplane.gateway;

public record SignedInnerCert(String certificateLine, byte[] certificateBlob, String keyId, long validAfterEpochSeconds,
		long validBeforeEpochSeconds) {
}
