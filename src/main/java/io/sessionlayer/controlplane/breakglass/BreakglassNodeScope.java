package io.sessionlayer.controlplane.breakglass;

import java.util.UUID;
import tools.jackson.databind.JsonNode;

/**
 * Node-scope check for a break-glass credential/code (FR-ACC-6). Fail-closed: a
 * scoped credential against an unknown node does not match.
 */
final class BreakglassNodeScope {

	private BreakglassNodeScope() {
	}

	static boolean permits(JsonNode selector, UUID nodeId) {
		if (selector == null || selector.isNull() || selector.isEmpty()) {
			return true;
		}
		if (nodeId == null) {
			return false;
		}
		JsonNode nodeIds = selector.get("node_ids");
		if (nodeIds != null && nodeIds.isArray()) {
			String wanted = nodeId.toString();
			for (JsonNode element : nodeIds) {
				if (element.isString() && wanted.equals(element.stringValue())) {
					return true;
				}
			}
		}
		return false;
	}
}
