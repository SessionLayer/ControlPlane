package io.sessionlayer.controlplane.data.runtime;

import java.util.UUID;
import org.springframework.data.r2dbc.repository.Query;
import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

public interface PinRepository extends ReactiveCrudRepository<Pin, UUID> {

	Mono<Pin> findByFingerprintAndIdentity(String fingerprint, String identity);

	Flux<Pin> findByIdentity(String identity);

	@Query("""
			SELECT * FROM runtime.pin
			WHERE fingerprint = :fingerprint AND revoked_at IS NULL AND expires_at > now()
			  AND (source_cidr IS NULL OR (:sourceIp <> '' AND :sourceIp::inet <<= source_cidr::inet))""")
	Flux<Pin> findActiveByFingerprintForSource(String fingerprint, String sourceIp);
}
