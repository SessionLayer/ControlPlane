package io.sessionlayer.controlplane.data.config;

import java.util.UUID;
import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import reactor.core.publisher.Mono;

public interface NodePolicyRepository extends ReactiveCrudRepository<NodePolicy, UUID> {

	Mono<NodePolicy> findByName(String name);
}
