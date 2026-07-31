package io.sessionlayer.controlplane.gateway;

import io.sessionlayer.controlplane.data.runtime.SessionSigningToken;
import io.sessionlayer.controlplane.data.runtime.SessionSigningTokenRepository;
import io.sessionlayer.controlplane.mtls.MtlsProperties;
import java.time.Instant;
import java.util.List;
import java.util.Objects;
import java.util.UUID;
import org.springframework.dao.OptimisticLockingFailureException;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

@Service
public class SessionSigningTokenService {

	private final SessionSigningTokenRepository tokens;
	private final MtlsProperties properties;

	public SessionSigningTokenService(SessionSigningTokenRepository tokens, MtlsProperties properties) {
		this.tokens = tokens;
		this.properties = properties;
	}

	/**
	 * Mint a single-use session-signing token; returns the raw token (shown once).
	 */
	public Mono<String> mint(UUID gatewayId, UUID sessionId, UUID nodeId, String principal, List<String> capabilities,
			String sourceAddress) {
		SingleUseTokens.Minted minted = SingleUseTokens.mint();
		Instant expiresAt = Instant.now().plus(properties.getSessionSigningTokenTtl());
		return tokens.save(SessionSigningToken.create(minted.hash(), gatewayId, sessionId, nodeId, principal,
				capabilities, sourceAddress, expiresAt)).thenReturn(minted.raw());
	}

	/**
	 * Validate the token is bound to {@code callerGatewayId} (and agrees with any
	 * advisory {@code context}), then atomically mark it used. Any unknown /
	 * cross-gateway / cross-session / expired / already-used token — or a lost
	 * consume race — is rejected with one generic {@code PERMISSION_DENIED}.
	 */
	public Mono<SessionSigningToken> consume(String rawToken, UUID callerGatewayId, SignRequestContext context) {
		if (rawToken == null || rawToken.isBlank() || callerGatewayId == null) {
			return Mono.error(denied());
		}
		String hash = SingleUseTokens.hash(rawToken);
		Instant now = Instant.now();
		SignRequestContext ctx = (context == null) ? SignRequestContext.EMPTY : context;
		return tokens.findByTokenHash(hash).switchIfEmpty(Mono.error(denied())).flatMap(token -> {
			if (!callerGatewayId.equals(token.gatewayId()) || token.used() || !token.expiresAt().isAfter(now)
					|| contextDisagrees(ctx, token)) {
				return Mono.error(denied());
			}
			SessionSigningToken used = new SessionSigningToken(token.id(), token.tokenHash(), token.gatewayId(),
					token.sessionId(), token.nodeId(), token.principal(), token.capabilities(), token.sourceAddress(),
					token.expiresAt(), true, now, token.version(), token.createdAt());
			return tokens.save(used).onErrorMap(OptimisticLockingFailureException.class, race -> denied());
		});
	}

	// The context is advisory: a field is checked only when the caller set it, and
	// when set it MUST equal the token's authoritative value.
	private static boolean contextDisagrees(SignRequestContext ctx, SessionSigningToken token) {
		if (ctx.sessionId() != null && !ctx.sessionId().equals(token.sessionId())) {
			return true;
		}
		if (ctx.nodeId() != null && !ctx.nodeId().equals(token.nodeId())) {
			return true;
		}
		return ctx.principal() != null && !Objects.equals(ctx.principal(), token.principal());
	}

	private static GatewayRequestException denied() {
		return new GatewayRequestException(GatewayRequestException.Reason.PERMISSION_DENIED,
				"session signing request refused");
	}
}
