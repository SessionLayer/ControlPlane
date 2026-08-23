package io.sessionlayer.controlplane.data.runtime;

import java.util.UUID;
import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import reactor.core.publisher.Mono;

public interface OidcLoginRepository extends ReactiveCrudRepository<OidcLogin, UUID> {

	Mono<OidcLogin> findByStateHash(String stateHash);
}
