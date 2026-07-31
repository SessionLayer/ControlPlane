package io.sessionlayer.controlplane.security;

import io.sessionlayer.controlplane.platform.PlatformSubject;
import java.util.List;

public record AuthenticatedPrincipal(String identity, List<String> groups, AuthMethod method) {

	public AuthenticatedPrincipal {
		groups = (groups == null) ? List.of() : List.copyOf(groups);
	}

	public PlatformSubject toPlatformSubject() {
		return new PlatformSubject(identity, groups);
	}
}
