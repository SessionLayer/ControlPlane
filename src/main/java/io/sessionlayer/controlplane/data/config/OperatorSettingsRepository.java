package io.sessionlayer.controlplane.data.config;

import java.util.UUID;
import org.springframework.data.r2dbc.repository.Query;
import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import reactor.core.publisher.Mono;

public interface OperatorSettingsRepository extends ReactiveCrudRepository<OperatorSettings, UUID> {

	@Query("SELECT * FROM config.operator_settings WHERE singleton = true")
	Mono<OperatorSettings> findSingleton();
}
