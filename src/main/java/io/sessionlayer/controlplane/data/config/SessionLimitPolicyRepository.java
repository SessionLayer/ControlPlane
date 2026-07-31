package io.sessionlayer.controlplane.data.config;

import java.util.UUID;
import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import reactor.core.publisher.Mono;

public interface SessionLimitPolicyRepository extends ReactiveCrudRepository<SessionLimitPolicy, UUID> {

	Mono<SessionLimitPolicy> findByName(String name);
}
