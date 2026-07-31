package io.sessionlayer.controlplane.data.runtime;

import java.util.UUID;
import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import reactor.core.publisher.Flux;

public interface BreakglassOfflineCodeRepository extends ReactiveCrudRepository<BreakglassOfflineCode, UUID> {

	Flux<BreakglassOfflineCode> findByIdentity(String identity);
}
