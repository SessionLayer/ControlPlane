package io.sessionlayer.controlplane.data.runtime;

import java.util.UUID;
import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import reactor.core.publisher.Mono;

public interface OtpRepository extends ReactiveCrudRepository<Otp, UUID> {

	Mono<Otp> findByOtpHash(String otpHash);
}
