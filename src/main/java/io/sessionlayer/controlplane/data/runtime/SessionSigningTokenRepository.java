package io.sessionlayer.controlplane.data.runtime;

import java.util.UUID;
import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import reactor.core.publisher.Mono;

public interface SessionSigningTokenRepository extends ReactiveCrudRepository<SessionSigningToken, UUID> {

	Mono<SessionSigningToken> findByTokenHash(String tokenHash);
}
