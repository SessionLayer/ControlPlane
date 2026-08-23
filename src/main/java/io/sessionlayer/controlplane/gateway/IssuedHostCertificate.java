package io.sessionlayer.controlplane.gateway;

public record IssuedHostCertificate(String certificateLine, byte[] certificateBlob, long validAfterEpochSeconds,
		long validBeforeEpochSeconds) {
}
