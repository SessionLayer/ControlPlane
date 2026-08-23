package io.sessionlayer.controlplane.gateway;

import io.sessionlayer.controlplane.data.runtime.GatewayEnrollmentToken;
import io.sessionlayer.controlplane.data.runtime.GatewayEnrollmentTokenRepository;
import io.sessionlayer.controlplane.mtls.MtlsProperties;
import java.time.Duration;
import java.time.Instant;
import java.util.UUID;
import org.springframework.dao.OptimisticLockingFailureException;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

@Service
public class GatewayEnrollmentTokenService {

	private final GatewayEnrollmentTokenRepository tokens;
	private final MtlsProperties properties;

	public GatewayEnrollmentTokenService(GatewayEnrollmentTokenRepository tokens, MtlsProperties properties) {
		this.tokens = tokens;
		this.properties = properties;
	}

	public record MintedEnrollmentToken(UUID id, String rawToken, String gatewayName, Instant expiresAt) {
	}

	public Mono<String> mint(String gatewayName, String createdBy) {
		return mint(gatewayName, createdBy, properties.getEnrollmentTokenTtl()).map(MintedEnrollmentToken::rawToken);
	}

	public Mono<MintedEnrollmentToken> mint(String gatewayName, String createdBy, Duration ttl) {
		SingleUseTokens.Minted minted = SingleUseTokens.mint();
		Instant expiresAt = Instant.now().plus(ttl);
		return tokens.save(GatewayEnrollmentToken.create(minted.hash(), gatewayName, expiresAt, createdBy))
				.map(saved -> new MintedEnrollmentToken(saved.id(), minted.raw(), gatewayName, expiresAt));
	}

	public Flux<GatewayEnrollmentToken> listActive() {
		Instant now = Instant.now();
		return tokens.findByConsumedAtIsNull().filter(token -> token.expiresAt().isAfter(now));
	}

	/**
	 * Revoke by marking the token consumed - {@code cp_runtime} holds no DELETE on
	 * this table and the enrollment path already refuses a consumed token.
	 * Idempotent: absent / already-consumed is a no-op, and losing the optimistic
	 * race means a concurrent consume already reached the same end state.
	 */
	public Mono<Void> revoke(UUID id) {
		Instant now = Instant.now();
		return tokens.findById(id).filter(token -> token.consumedAt() == null)
				.flatMap(token -> tokens.save(consumed(token, now))
						.onErrorResume(OptimisticLockingFailureException.class, race -> Mono.empty()))
				.then();
	}

	public Mono<Boolean> isValid(String rawToken, String gatewayName) {
		if (rawToken == null || rawToken.isBlank()) {
			return Mono.just(false);
		}
		String hash = SingleUseTokens.hash(rawToken);
		Instant now = Instant.now();
		return tokens.findByTokenHash(hash).map(token -> token.gatewayName().equals(gatewayName)
				&& token.consumedAt() == null && token.expiresAt().isAfter(now)).defaultIfEmpty(false);
	}

	public Mono<GatewayEnrollmentToken> consume(String rawToken, String gatewayName) {
		if (rawToken == null || rawToken.isBlank()) {
			return Mono.error(invalid());
		}
		String hash = SingleUseTokens.hash(rawToken);
		Instant now = Instant.now();
		return tokens.findByTokenHash(hash).switchIfEmpty(Mono.error(invalid())).flatMap(token -> {
			if (!token.gatewayName().equals(gatewayName) || token.consumedAt() != null
					|| !token.expiresAt().isAfter(now)) {
				return Mono.error(invalid());
			}
			return tokens.save(consumed(token, now)).onErrorMap(OptimisticLockingFailureException.class,
					race -> invalid());
		});
	}

	private static GatewayEnrollmentToken consumed(GatewayEnrollmentToken token, Instant at) {
		return new GatewayEnrollmentToken(token.id(), token.tokenHash(), token.gatewayName(), token.singleUse(),
				token.expiresAt(), at, token.createdBy(), token.version(), token.createdAt());
	}

	private static GatewayRequestException invalid() {
		return new GatewayRequestException(GatewayRequestException.Reason.UNAUTHENTICATED, "enrollment token invalid");
	}
}
