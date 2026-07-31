package io.sessionlayer.controlplane.data.config;

import java.util.UUID;
import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import reactor.core.publisher.Mono;

public interface JitPolicyRepository extends ReactiveCrudRepository<JitPolicy, UUID> {

	Mono<JitPolicy> findByName(String name);
}
