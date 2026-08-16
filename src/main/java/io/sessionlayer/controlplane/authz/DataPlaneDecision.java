package io.sessionlayer.controlplane.authz;

import java.util.List;
import java.util.Set;
import java.util.UUID;

public record DataPlaneDecision(Effect effect, Reason reason, Set<String> allowedLogins, Set<String> capabilities,
		int grantTtlSeconds, UUID matchedRuleId, String matchedRuleName) {

	public enum Effect {
		ALLOW, DENY
	}

	/** The decision-log reason (server-side only). */
	public enum Reason {
		ALLOWED,
		LOCKED,
		EXPLICIT_DENY,
		NO_MATCHING_ALLOW,
		PRINCIPAL_NOT_ALLOWED,
		EVALUATION_ERROR
	}

	public boolean allowed() {
		return effect == Effect.ALLOW;
	}

	static DataPlaneDecision allow(Set<String> logins, Set<String> capabilities, int grantTtlSeconds, UUID ruleId,
			String ruleName) {
		return new DataPlaneDecision(Effect.ALLOW, Reason.ALLOWED, Set.copyOf(logins), Set.copyOf(capabilities),
				grantTtlSeconds, ruleId, ruleName);
	}

	static DataPlaneDecision deny(Reason reason, UUID ruleId, String ruleName) {
		return new DataPlaneDecision(Effect.DENY, reason, Set.of(), Set.of(), 0, ruleId, ruleName);
	}

	public List<String> sortedLogins() {
		return allowedLogins.stream().sorted().toList();
	}

	public List<String> sortedCapabilities() {
		return capabilities.stream().sorted().toList();
	}
}
