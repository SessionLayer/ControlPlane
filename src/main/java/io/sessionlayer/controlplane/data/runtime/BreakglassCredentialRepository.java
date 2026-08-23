package io.sessionlayer.controlplane.data.runtime;

import java.util.UUID;
import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

public interface BreakglassCredentialRepository extends ReactiveCrudRepository<BreakglassCredential, UUID> {

	Mono<BreakglassCredential> findByKeyFingerprint(String keyFingerprint);

	Flux<BreakglassCredential> findByIdentity(String identity);
}
