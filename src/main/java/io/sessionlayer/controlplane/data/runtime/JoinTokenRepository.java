package io.sessionlayer.controlplane.data.runtime;

import java.util.UUID;
import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

public interface JoinTokenRepository extends ReactiveCrudRepository<JoinToken, UUID> {

	Mono<JoinToken> findByTokenHash(String tokenHash);

	Flux<JoinToken> findByConsumedAtIsNull();
}
