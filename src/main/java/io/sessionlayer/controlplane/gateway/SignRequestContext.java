package io.sessionlayer.controlplane.gateway;

import java.util.UUID;

public record SignRequestContext(UUID sessionId, UUID nodeId, String principal) {

	public static final SignRequestContext EMPTY = new SignRequestContext(null, null, null);
}
