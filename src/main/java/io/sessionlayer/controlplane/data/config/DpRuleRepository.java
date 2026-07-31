package io.sessionlayer.controlplane.data.config;

import java.util.UUID;
import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

public interface DpRuleRepository extends ReactiveCrudRepository<DpRule, UUID> {

	Mono<DpRule> findByName(String name);

	Flux<DpRule> findByEffect(String effect);
}
