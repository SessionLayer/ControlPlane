package io.sessionlayer.controlplane.mtls;

import java.util.Optional;
import java.util.UUID;

public final class AgentIdentityUri {

	private static final String PREFIX = "sessionlayer://agent/";

	private AgentIdentityUri() {
	}

	public static String of(UUID agentId) {
		return PREFIX + agentId;
	}

	public static Optional<UUID> parse(String uri) {
		if (uri == null || !uri.startsWith(PREFIX)) {
			return Optional.empty();
		}
		try {
			return Optional.of(UUID.fromString(uri.substring(PREFIX.length())));
		} catch (IllegalArgumentException notAUuid) {
			return Optional.empty();
		}
	}
}
