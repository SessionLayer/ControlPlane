package io.sessionlayer.controlplane.gateway;

import java.util.List;

public record IssuedServerCertificate(byte[] certificate, List<byte[]> caChain, String gatewayName,
		long notBeforeEpochSeconds, long notAfterEpochSeconds) {
}
