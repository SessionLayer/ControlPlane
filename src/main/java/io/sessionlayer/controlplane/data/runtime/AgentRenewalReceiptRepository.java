package io.sessionlayer.controlplane.data.runtime;

import java.util.UUID;
import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import reactor.core.publisher.Mono;

public interface AgentRenewalReceiptRepository extends ReactiveCrudRepository<AgentRenewalReceipt, UUID> {

	Mono<AgentRenewalReceipt> findByAgentIdAndPriorGenerationAndCsrPublicKeyHash(UUID agentId, long priorGeneration,
			String csrPublicKeyHash);
}
