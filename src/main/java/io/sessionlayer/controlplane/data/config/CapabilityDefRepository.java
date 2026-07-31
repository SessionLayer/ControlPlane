package io.sessionlayer.controlplane.data.config;

import java.util.UUID;
import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import reactor.core.publisher.Mono;

public interface CapabilityDefRepository extends ReactiveCrudRepository<CapabilityDef, UUID> {

	Mono<CapabilityDef> findByName(String name);
}
