package io.sessionlayer.controlplane.agent;

import java.util.List;
import java.util.UUID;

public record IssuedAgentIdentity(byte[] certificate, List<byte[]> caChain, UUID agentId, UUID nodeId, long generation,
		long notBeforeEpochSeconds, long notAfterEpochSeconds) {
}
