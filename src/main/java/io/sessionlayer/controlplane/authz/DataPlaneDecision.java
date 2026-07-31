package io.sessionlayer.controlplane.authz;

import java.util.List;
import java.util.Set;
import java.util.UUID;

/**
 * Result of data-plane RBAC evaluation. Effect is the generic outcome; reason/
 * matchedRule* are decision-log detail (server-side only, never disclosed). On
 * allow, allowedLogins/capabilities/grantTtlSeconds are populated; on deny they
 * are empty.
 */
public record DataPlaneDecision(Effect effect, Reason reason, Set<String> allowedLogins, Set<String> capabilities,
		int grantTtlSeconds, UUID matchedRuleId, String matchedRuleName) {

	public enum Effect {
		ALLOW, DENY
	}

	/** The decision-log reason (server-side only). */
	public enum Reason {
		ALLOWED,
		/** access_lock matched—un-overridable deny. */
		LOCKED,
		/** Applicable deny rule won (deny-overrides). */
		EXPLICIT_DENY,
		/** No applicable allow (default-deny). */
		NO_MATCHING_ALLOW,
		/** Requested login not in allowed set. */
		PRINCIPAL_NOT_ALLOWED,
		/** Malformed rule/lock/selector or datastore problem—fail closed. */
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

	/** Deterministic sorted view of the allowed logins (for the signed context). */
	public List<String> sortedLogins() {
		return allowedLogins.stream().sorted().toList();
	}

	public List<String> sortedCapabilities() {
		return capabilities.stream().sorted().toList();
	}
}
