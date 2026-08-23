package io.sessionlayer.controlplane.agent;

import java.util.UUID;
import reactor.core.publisher.Mono;

public interface AgentSecurityAlertSink {

	Mono<Void> cloneDetected(UUID agentId, UUID nodeId, long expectedGeneration, long presentedGeneration);
}
