package io.sessionlayer.controlplane.agent;

import java.util.List;
import java.util.UUID;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

@Component
public class AgentSecurityAlerts {

	private final List<AgentSecurityAlertSink> sinks;

	public AgentSecurityAlerts(List<AgentSecurityAlertSink> sinks) {
		this.sinks = sinks;
	}

	public Mono<Void> cloneDetected(UUID agentId, UUID nodeId, long expectedGeneration, long presentedGeneration) {
		return Flux.fromIterable(sinks)
				.flatMap(sink -> sink.cloneDetected(agentId, nodeId, expectedGeneration, presentedGeneration)
						.onErrorResume(failed -> Mono.empty()))
				.then();
	}
}
