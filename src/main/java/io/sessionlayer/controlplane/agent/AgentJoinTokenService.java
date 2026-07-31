package io.sessionlayer.controlplane.agent;

import io.sessionlayer.controlplane.data.runtime.JoinToken;
import io.sessionlayer.controlplane.data.runtime.JoinTokenRepository;
import io.sessionlayer.controlplane.gateway.SingleUseTokens;
import java.time.Duration;
import java.time.Instant;
import org.springframework.dao.OptimisticLockingFailureException;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.node.JsonNodeFactory;
import tools.jackson.databind.node.ObjectNode;

@Service
public class AgentJoinTokenService {

	private final JoinTokenRepository tokens;

	public AgentJoinTokenService(JoinTokenRepository tokens) {
		this.tokens = tokens;
	}

	public record MintedJoinToken(java.util.UUID id, String rawToken, String nodeName, Instant expiresAt) {
	}

	public Mono<MintedJoinToken> mint(String nodeName, String createdBy, Duration ttl) {
		SingleUseTokens.Minted minted = SingleUseTokens.mint();
		Instant expiresAt = Instant.now().plus(ttl);
		JoinToken token = JoinToken.create(minted.hash(), scopeFor(nodeName), "token", null, true, expiresAt,
				createdBy);
		return tokens.save(token).map(saved -> new MintedJoinToken(saved.id(), minted.raw(), nodeName, expiresAt));
	}

	public Mono<Boolean> isValid(String rawToken, String nodeName) {
		if (rawToken == null || rawToken.isBlank()) {
			return Mono.just(false);
		}
		Instant now = Instant.now();
		return tokens.findByTokenHash(SingleUseTokens.hash(rawToken)).map(token -> authorizes(token, nodeName, now))
				.defaultIfEmpty(false);
	}

	public Mono<JoinToken> consume(String rawToken, String nodeName) {
		if (rawToken == null || rawToken.isBlank()) {
			return Mono.error(invalid());
		}
		Instant now = Instant.now();
		return tokens.findByTokenHash(SingleUseTokens.hash(rawToken)).switchIfEmpty(Mono.error(invalid()))
				.flatMap(token -> {
					if (!authorizes(token, nodeName, now)) {
						return Mono.error(invalid());
					}
					JoinToken consumed = new JoinToken(token.id(), token.tokenHash(), token.scope(), token.joinMethod(),
							token.nodeId(), token.singleUse(), token.expiresAt(), now, token.createdBy(),
							token.version(), token.createdAt());
					return tokens.save(consumed).onErrorMap(OptimisticLockingFailureException.class, race -> invalid());
				});
	}

	public Flux<JoinToken> listActive() {
		Instant now = Instant.now();
		return tokens.findByConsumedAtIsNull().filter(token -> token.expiresAt().isAfter(now));
	}

	public Mono<Void> revoke(java.util.UUID id) {
		return tokens.deleteById(id);
	}

	public static String scopedNodeName(JoinToken token) {
		JsonNode name = token.scope() == null ? null : token.scope().get("node_name");
		return (name != null && name.isString()) ? name.stringValue() : null;
	}

	private static boolean authorizes(JoinToken token, String nodeName, Instant now) {
		return "token".equals(token.joinMethod()) && token.consumedAt() == null && token.expiresAt().isAfter(now)
				&& nodeName != null && nodeName.equals(scopedNodeName(token));
	}

	private static ObjectNode scopeFor(String nodeName) {
		ObjectNode scope = JsonNodeFactory.instance.objectNode();
		scope.put("node_name", nodeName);
		return scope;
	}

	private static AgentJoinException invalid() {
		return new AgentJoinException(AgentJoinException.Reason.UNAUTHENTICATED, "join token invalid");
	}
}
