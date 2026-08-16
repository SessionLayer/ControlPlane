package io.sessionlayer.controlplane.security;

import io.sessionlayer.controlplane.platform.PlatformAuthorization;
import io.sessionlayer.controlplane.platform.PlatformPermissions;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationResult;
import org.springframework.security.authorization.ReactiveAuthorizationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.server.authorization.AuthorizationContext;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

@Component
public class MetricsAuthorizationManager implements ReactiveAuthorizationManager<AuthorizationContext> {

	private static final AuthorizationResult DENY = new AuthorizationDecision(false);

	private final PlatformAuthorization platformAuthorization;

	public MetricsAuthorizationManager(PlatformAuthorization platformAuthorization) {
		this.platformAuthorization = platformAuthorization;
	}

	@Override
	public Mono<AuthorizationResult> authorize(Mono<Authentication> authentication, AuthorizationContext context) {
		// Read the principal from the Authentication the chain hands us rather than
		// from the context holder: this runs as part of the authorization step, so the
		// argument is the authoritative one.
		return authentication.filter(auth -> auth.isAuthenticated()).map(Authentication::getPrincipal)
				.filter(AuthenticatedPrincipal.class::isInstance)
				.map(principal -> ((AuthenticatedPrincipal) principal).toPlatformSubject())
				.flatMap(subject -> platformAuthorization.authorize(subject, PlatformPermissions.METRICS_READ, null))
				.<AuthorizationResult>map(decision -> new AuthorizationDecision(decision.allowed()))
				.defaultIfEmpty(DENY).onErrorReturn(DENY);
	}
}
