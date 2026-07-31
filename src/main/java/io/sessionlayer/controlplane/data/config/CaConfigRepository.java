package io.sessionlayer.controlplane.data.config;

import java.util.UUID;
import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

public interface CaConfigRepository extends ReactiveCrudRepository<CaConfig, UUID> {

	Flux<CaConfig> findByCaKind(String caKind);

	Mono<CaConfig> findByCaKindAndRotationState(String caKind, String rotationState);

	Mono<CaConfig> findByName(String name);
}
