package io.sessionlayer.controlplane.data.config;

import java.util.UUID;
import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import reactor.core.publisher.Mono;

public interface BreakglassPolicyRepository extends ReactiveCrudRepository<BreakglassPolicy, UUID> {

	Mono<BreakglassPolicy> findByName(String name);
}
