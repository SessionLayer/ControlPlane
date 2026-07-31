package io.sessionlayer.controlplane.data.runtime;

import java.util.UUID;
import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import reactor.core.publisher.Mono;

public interface RecordingTokenRepository extends ReactiveCrudRepository<RecordingToken, UUID> {

	Mono<RecordingToken> findByTokenHash(String tokenHash);
}
