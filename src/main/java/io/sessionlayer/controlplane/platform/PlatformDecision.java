package io.sessionlayer.controlplane.platform;

import java.util.UUID;

public record PlatformDecision(boolean allowed, Reason reason, UUID matchedRoleId, String matchedRoleName) {

	public enum Reason {
		ALLOWED, NO_GRANTING_BINDING, OUT_OF_SCOPE, EVALUATION_ERROR
	}

	static PlatformDecision allow(UUID roleId, String roleName) {
		return new PlatformDecision(true, Reason.ALLOWED, roleId, roleName);
	}

	static PlatformDecision deny(Reason reason) {
		return new PlatformDecision(false, reason, null, null);
	}
}
