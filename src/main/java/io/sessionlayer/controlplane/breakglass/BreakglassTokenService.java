package io.sessionlayer.controlplane.breakglass;

import io.sessionlayer.controlplane.data.runtime.BreakglassToken;
import io.sessionlayer.controlplane.data.runtime.BreakglassTokenRepository;
import io.sessionlayer.controlplane.gateway.SingleUseTokens;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.springframework.dao.OptimisticLockingFailureException;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

/**
 * Mints and atomically consumes the single-use break-glass token. Bound to
 * {gatewayId, identity, nodeId, sourceAddress, exp}, carrying the credential's
 * scoped allowedPrincipals. Stores hash only. Fail closed on any mismatch;
 * never distinguishes reason (deny).
 */
@Service
public class BreakglassTokenService {

	private final BreakglassTokenRepository tokens;
	private final BreakglassProperties properties;

	public BreakglassTokenService(BreakglassTokenRepository tokens, BreakglassProperties properties) {
		this.tokens = tokens;
		this.properties = properties;
	}

	public Mono<String> mint(UUID gatewayId, String identity, UUID nodeId, List<String> allowedPrincipals,
			String sourceAddress) {
		SingleUseTokens.Minted minted = SingleUseTokens.mint();
		Instant expiresAt = Instant.now().plus(properties.getTokenTtl());
		return tokens
				.save(BreakglassToken.create(minted.hash(), gatewayId, identity, nodeId,
						allowedPrincipals == null ? List.of() : allowedPrincipals, sourceAddress, expiresAt))
				.thenReturn(minted.raw());
	}

	public Mono<BreakglassToken> consume(String rawToken, UUID callerGatewayId, String identity, UUID nodeId,
			String sourceIp) {
		if (rawToken == null || rawToken.isBlank() || callerGatewayId == null) {
			return Mono.empty();
		}
		String hash = SingleUseTokens.hash(rawToken);
		Instant now = Instant.now();
		return tokens.findByTokenHash(hash).flatMap(token -> {
			if (!callerGatewayId.equals(token.gatewayId()) || !equalsNonNull(token.identity(), identity) || token.used()
					|| !token.expiresAt().isAfter(now) || nodeMismatch(token.nodeId(), nodeId)
					|| sourceMismatch(token.sourceAddress(), sourceIp)) {
				return Mono.<BreakglassToken>empty();
			}
			return tokens.save(token.consumed(now)).onErrorResume(OptimisticLockingFailureException.class,
					race -> Mono.empty());
		});
	}

	private static boolean nodeMismatch(UUID tokenNode, UUID requestNode) {
		// A fleet-scoped token (no node binding) tolerates any node; a bound token must
		// match the Authorize node exactly.
		return tokenNode != null && !tokenNode.equals(requestNode);
	}

	private static boolean sourceMismatch(String tokenSource, String requestSource) {
		// Source is a deny-only binding: a bound token requires the same source.
		return tokenSource != null && !tokenSource.equals(requestSource);
	}

	private static boolean equalsNonNull(String a, String b) {
		return a != null && a.equals(b);
	}
}
