package io.sessionlayer.controlplane.data.runtime;

import java.util.UUID;
import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

public interface GatewayEnrollmentTokenRepository extends ReactiveCrudRepository<GatewayEnrollmentToken, UUID> {

	Mono<GatewayEnrollmentToken> findByTokenHash(String tokenHash);

	Flux<GatewayEnrollmentToken> findByConsumedAtIsNull();
}
