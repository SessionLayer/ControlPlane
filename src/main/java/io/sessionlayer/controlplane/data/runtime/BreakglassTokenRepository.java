package io.sessionlayer.controlplane.data.runtime;

import java.util.UUID;
import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import reactor.core.publisher.Mono;

public interface BreakglassTokenRepository extends ReactiveCrudRepository<BreakglassToken, UUID> {

	Mono<BreakglassToken> findByTokenHash(String tokenHash);
}
