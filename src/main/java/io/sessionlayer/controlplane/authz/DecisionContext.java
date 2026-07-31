package io.sessionlayer.controlplane.authz;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.UUID;

/**
 * Decision context before signing. grantExpiry = min(grant/cred TTL ceilings);
 * policyEpoch is the CP monotonic epoch. identity/groups/labels are SIGNED for
 * trusted lock matching on hot path. accessModel/idleTimeoutSeconds signed for
 * per-model behavior (TIGHTEN-ONLY, N-1 compatible).
 */
public record DecisionContext(UUID nodeId, String nodeName, List<String> allowedLogins, List<String> capabilities,
		String principal, Instant grantExpiry, long policyEpoch, Duration decisionTtl, UUID gatewayId, UUID sessionId,
		String sourceAddress, Instant issuedAt, String identity, List<String> identityGroups, List<String> nodeLabels,
		String accessModel, Integer idleTimeoutSeconds) {

	public DecisionContext {
		allowedLogins = List.copyOf(allowedLogins);
		capabilities = List.copyOf(capabilities);
		identityGroups = List.copyOf(identityGroups);
		nodeLabels = List.copyOf(nodeLabels);
	}
}
