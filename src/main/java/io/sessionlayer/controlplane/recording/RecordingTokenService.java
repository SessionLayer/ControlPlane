package io.sessionlayer.controlplane.recording;

import io.sessionlayer.controlplane.data.runtime.RecordingToken;
import io.sessionlayer.controlplane.data.runtime.RecordingTokenRepository;
import io.sessionlayer.controlplane.gateway.GatewayRequestException;
import io.sessionlayer.controlplane.gateway.SingleUseTokens;
import io.sessionlayer.controlplane.mtls.MtlsProperties;
import java.time.Instant;
import java.util.Objects;
import java.util.UUID;
import org.springframework.dao.OptimisticLockingFailureException;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

@Service
public class RecordingTokenService {

	private final RecordingTokenRepository tokens;
	private final MtlsProperties properties;

	public RecordingTokenService(RecordingTokenRepository tokens, MtlsProperties properties) {
		this.tokens = tokens;
		this.properties = properties;
	}

	public Mono<String> mint(UUID gatewayId, UUID sessionId, UUID nodeId, String principal, String sourceAddress) {
		SingleUseTokens.Minted minted = SingleUseTokens.mint();
		Instant expiresAt = Instant.now().plus(properties.getSessionSigningTokenTtl());
		return tokens.save(
				RecordingToken.create(minted.hash(), gatewayId, sessionId, nodeId, principal, sourceAddress, expiresAt))
				.thenReturn(minted.raw());
	}

	public Mono<RecordingToken> consume(String rawToken, UUID callerGatewayId, RecordingRequestContext context) {
		if (rawToken == null || rawToken.isBlank() || callerGatewayId == null) {
			return Mono.error(denied());
		}
		String hash = SingleUseTokens.hash(rawToken);
		Instant now = Instant.now();
		RecordingRequestContext ctx = (context == null) ? RecordingRequestContext.EMPTY : context;
		return tokens.findByTokenHash(hash).switchIfEmpty(Mono.error(denied())).flatMap(token -> {
			if (!callerGatewayId.equals(token.gatewayId()) || token.used() || !token.expiresAt().isAfter(now)
					|| contextDisagrees(ctx, token)) {
				return Mono.error(denied());
			}
			RecordingToken used = new RecordingToken(token.id(), token.tokenHash(), token.gatewayId(),
					token.sessionId(), token.nodeId(), token.principal(), token.sourceAddress(), token.expiresAt(),
					true, now, token.version(), token.createdAt());
			return tokens.save(used).onErrorMap(OptimisticLockingFailureException.class, race -> denied());
		});
	}

	private static boolean contextDisagrees(RecordingRequestContext ctx, RecordingToken token) {
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
				"recording request refused");
	}
}
