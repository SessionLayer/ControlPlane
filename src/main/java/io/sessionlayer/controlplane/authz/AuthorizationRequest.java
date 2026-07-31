package io.sessionlayer.controlplane.authz;

import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * Resolved decision input for the data-plane evaluator. Source IP is deny-only;
 * fails closed if unknown.
 */
public record AuthorizationRequest(String identity, List<String> groups, UUID nodeId, Map<String, String> nodeLabels,
		String sourceIp, String requestedPrincipal) {

	public AuthorizationRequest {
		groups = (groups == null) ? List.of() : List.copyOf(groups);
		nodeLabels = (nodeLabels == null) ? Map.of() : Map.copyOf(nodeLabels);
	}
}
