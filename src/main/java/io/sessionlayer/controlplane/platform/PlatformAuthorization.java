package io.sessionlayer.controlplane.platform;

import java.util.List;
import reactor.core.publisher.Mono;
import tools.jackson.databind.JsonNode;

public interface PlatformAuthorization {

	Mono<PlatformDecision> authorize(PlatformSubject subject, String permission, PlatformScope scope);

	/** Resolve scope grant for filtering results (not gating). Does not audit. */
	Mono<ScopeGrant> resolveScopeGrant(PlatformSubject subject, String permission);

	record ScopeGrant(boolean granted, boolean unrestricted, List<JsonNode> scopes) {

		public ScopeGrant {
			scopes = (scopes == null) ? List.of() : List.copyOf(scopes);
		}

		public static ScopeGrant deny() {
			return new ScopeGrant(false, false, List.of());
		}

		public static ScopeGrant all() {
			return new ScopeGrant(true, true, List.of());
		}

		public static ScopeGrant scoped(List<JsonNode> scopes) {
			return new ScopeGrant(true, false, scopes);
		}
	}
}
