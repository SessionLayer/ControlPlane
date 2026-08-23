package io.sessionlayer.controlplane.data.runtime;

import java.util.UUID;
import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import reactor.core.publisher.Flux;

public interface BreakglassActivationRepository extends ReactiveCrudRepository<BreakglassActivation, UUID> {

	Flux<BreakglassActivation> findByReviewStatus(String reviewStatus);
}
