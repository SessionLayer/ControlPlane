package io.sessionlayer.controlplane.mtls;

import java.util.Optional;
import java.util.UUID;

public final class GatewayIdentityUri {

	private static final String PREFIX = "sessionlayer://gateway/";

	private GatewayIdentityUri() {
	}

	public static String of(UUID gatewayId) {
		return PREFIX + gatewayId;
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
