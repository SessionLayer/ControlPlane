package io.sessionlayer.controlplane.pin;

import io.sessionlayer.controlplane.audit.AuditEventStore;
import io.sessionlayer.controlplane.authz.AuthzProperties;
import io.sessionlayer.controlplane.data.runtime.Pin;
import io.sessionlayer.controlplane.data.runtime.PinRepository;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

@Service
public class PinService {

	private final PinRepository pins;
	private final AuthzProperties authzProperties;
	private final AuditEventStore audit;

	public PinService(PinRepository pins, AuthzProperties authzProperties, AuditEventStore audit) {
		this.pins = pins;
		this.authzProperties = authzProperties;
		this.audit = audit;
	}

	public Mono<Pin> create(String fingerprint, String identity, String sourceCidr, List<String> principals,
			long ttlSeconds, String actor) {
		if (fingerprint == null || fingerprint.isBlank() || identity == null || identity.isBlank() || principals == null
				|| principals.isEmpty()) {
			return Mono.error(new IllegalArgumentException("fingerprint, identity and principals are required"));
		}
		long cappedSeconds = Math.min(Math.max(1, ttlSeconds), authzProperties.getMaxGrantTtl().getSeconds());
		Instant expiresAt = Instant.now().plus(Duration.ofSeconds(cappedSeconds));
		return pins.findByFingerprintAndIdentity(fingerprint, identity)
				.map(existing -> existing.reissued(sourceCidr, principals, expiresAt))
				.defaultIfEmpty(Pin.create(fingerprint, identity, sourceCidr, principals, expiresAt))
				.flatMap(
						pins::save)
				.flatMap(saved -> audit.record(actor, identity, "pin.create", "success", null, null,
						Map.of("pin_id", saved.id().toString(), "fingerprint", fingerprint, "ttl_seconds",
								String.valueOf(cappedSeconds)))
						.thenReturn(saved));
	}

	public record Resolved(String identity, List<String> principals) {
	}

	public Mono<Resolved> resolveForSource(String fingerprint, String sourceIp) {
		if (fingerprint == null || fingerprint.isBlank()) {
			return Mono.empty();
		}
		String ip = sourceIp == null ? "" : sourceIp;
		return pins.findActiveByFingerprintForSource(fingerprint, ip).collectList().flatMap(matches -> {
			if (matches.size() != 1) {
				String reason = matches.isEmpty() ? "no_active_pin" : "ambiguous_fingerprint";
				return audit.record("system", null, "pin.resolve", "denied", null, null,
						Map.of("reason", reason, "source_ip", ip)).then(Mono.empty());
			}
			Pin pin = matches.get(0);
			return audit.record(pin.identity(), null, "pin.resolve", "success", null, null, Map.of())
					.thenReturn(new Resolved(pin.identity(), pin.principals()));
		}).onErrorResume(err -> audit.record("system", null, "pin.resolve", "error", null, null,
				Map.of("reason", "evaluation_error", "source_ip", ip)).then(Mono.empty()));
	}

	/**
	 * The unfiltered form is deliberate: a pin authenticates on its own and outlives
	 * the session it was created for, so one nobody has accounted for is standing
	 * access. It discloses nothing new — {@code user:manage}, the permission gating
	 * this read, also MINTS pins.
	 */
	public Flux<Pin> listActive(String identity) {
		Instant now = Instant.now();
		Flux<Pin> matching = (identity == null || identity.isBlank()) ? pins.findAll() : pins.findByIdentity(identity);
		return matching.filter(p -> p.active(now));
	}

	public Mono<Pin> revoke(UUID pinId, String actor, String reason) {
		return pins.findById(pinId).flatMap(pin -> {
			if (pin.revokedAt() != null) {
				return Mono.just(pin);
			}
			return pins.save(pin.revoked(Instant.now()))
					.flatMap(saved -> audit.record(actor, pin.identity(), "pin.revoke", "success", null, null,
							Map.of("pin_id", pinId.toString(), "reason", reason)).thenReturn(saved));
		});
	}

	public Mono<Long> revokeForIdentity(String identity, String actor, String reason) {
		Instant now = Instant.now();
		return pins.findByIdentity(identity).filter(p -> p.revokedAt() == null).flatMap(p -> pins.save(p.revoked(now)))
				.count().flatMap(
						count -> audit
								.record(actor, identity, "pin.revoke", "success", null, null,
										Map.of("reason", reason, "revoked_count", String.valueOf(count)))
								.thenReturn(count));
	}
}
