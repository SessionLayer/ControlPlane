package io.sessionlayer.controlplane.data.config;

import java.util.UUID;
import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import reactor.core.publisher.Mono;

public interface PlatformRoleRepository extends ReactiveCrudRepository<PlatformRole, UUID> {

	Mono<PlatformRole> findByName(String name);
}
