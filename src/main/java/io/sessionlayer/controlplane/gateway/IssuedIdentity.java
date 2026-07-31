package io.sessionlayer.controlplane.gateway;

import java.util.List;
import java.util.UUID;

public record IssuedIdentity(byte[] certificate, List<byte[]> caChain, UUID gatewayId, long generation,
		long notBeforeEpochSeconds, long notAfterEpochSeconds) {
}
