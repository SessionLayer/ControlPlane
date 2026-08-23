package io.sessionlayer.controlplane.agent;

import io.sessionlayer.controlplane.agent.AgentJoinProperties.Oidc;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Duration;
import java.util.concurrent.atomic.AtomicReference;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.BadJwtException;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.jwt.JwtIssuerValidator;
import org.springframework.security.oauth2.jwt.JwtTimestampValidator;
import org.springframework.security.oauth2.jwt.NimbusReactiveJwtDecoder;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

@Component
public class OidcJoinVerifier {

	private static final Duration DECODE_TIMEOUT = Duration.ofSeconds(15);

	private final AgentJoinProperties properties;
	private final AtomicReference<ReactiveJwtDecoder> delegate = new AtomicReference<>();

	public OidcJoinVerifier(AgentJoinProperties properties) {
		this.properties = properties;
	}

	public Mono<Void> verify(String workloadToken, String nodeName) {
		Oidc oidc = properties.getOidc();
		if (!oidc.isEnabled() || oidc.getIssuer() == null || oidc.getJwksUri() == null || oidc.getAudience() == null) {
			return Mono.error(unauthenticated());
		}
		if (workloadToken == null || workloadToken.isBlank()) {
			return Mono.error(unauthenticated());
		}
		return decoder(oidc).decode(workloadToken)
				.timeout(DECODE_TIMEOUT, Mono.error(new BadJwtException("workload token validation timed out")))
				.onErrorMap(JwtException.class, e -> unauthenticated()).flatMap(jwt -> {
					String claim = jwt.getClaimAsString(oidc.getNodeClaim());
					if (claim == null || !constantTimeEquals(claim, nodeName)) {
						return Mono.error(unauthenticated());
					}
					return Mono.empty();
				});
	}

	private ReactiveJwtDecoder decoder(Oidc oidc) {
		ReactiveJwtDecoder cached = delegate.get();
		if (cached != null) {
			return cached;
		}
		NimbusReactiveJwtDecoder decoder = NimbusReactiveJwtDecoder.withJwkSetUri(oidc.getJwksUri())
				.jwsAlgorithms(algs -> oidc.getAllowedAlgs().forEach(a -> algs.add(SignatureAlgorithm.from(a))))
				.build();
		decoder.setJwtValidator(jwtValidator(oidc));
		delegate.set(decoder);
		return decoder;
	}

	static OAuth2TokenValidator<Jwt> jwtValidator(Oidc oidc) {
		return new DelegatingOAuth2TokenValidator<>(new JwtTimestampValidator(oidc.getClockSkew()), requireExpiry(),
				new JwtIssuerValidator(oidc.getIssuer()), audience(oidc.getAudience()));
	}

	private static OAuth2TokenValidator<Jwt> requireExpiry() {
		return jwt -> jwt.getExpiresAt() != null
				? OAuth2TokenValidatorResult.success()
				: OAuth2TokenValidatorResult
						.failure(new OAuth2Error("invalid_token", "the workload token must carry exp", null));
	}

	private static OAuth2TokenValidator<Jwt> audience(String audience) {
		return jwt -> {
			var aud = jwt.getAudience();
			return aud != null && aud.contains(audience)
					? OAuth2TokenValidatorResult.success()
					: OAuth2TokenValidatorResult.failure(new OAuth2Error("invalid_token",
							"the workload token audience must contain " + "the agent-join audience", null));
		};
	}

	private static boolean constantTimeEquals(String a, String b) {
		return MessageDigest.isEqual(a.getBytes(StandardCharsets.UTF_8), b.getBytes(StandardCharsets.UTF_8));
	}

	private static AgentJoinException unauthenticated() {
		return new AgentJoinException(AgentJoinException.Reason.UNAUTHENTICATED, "enrollment refused");
	}
}
