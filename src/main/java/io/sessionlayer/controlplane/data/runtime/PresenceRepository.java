package io.sessionlayer.controlplane.data.runtime;

import java.util.UUID;
import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import reactor.core.publisher.Flux;

public interface PresenceRepository extends ReactiveCrudRepository<Presence, UUID> {

	Flux<Presence> findByOwningGateway(String owningGateway);
}
