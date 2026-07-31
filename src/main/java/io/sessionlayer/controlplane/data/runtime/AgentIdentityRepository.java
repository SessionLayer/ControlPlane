package io.sessionlayer.controlplane.data.runtime;

import java.util.UUID;
import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

public interface AgentIdentityRepository extends ReactiveCrudRepository<AgentIdentity, UUID> {

	Flux<AgentIdentity> findByNodeId(UUID nodeId);

	Mono<AgentIdentity> findByNodeIdAndStatus(UUID nodeId, String status);
}
