package io.sessionlayer.controlplane.jit;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.node.ArrayNode;
import tools.jackson.databind.node.ObjectNode;

public final class JitApprovalChain {

	public static final String KIND_EMAIL = "email";
	public static final String KIND_OIDC_GROUP = "oidc_group";

	private JitApprovalChain() {
	}

	public record Level(String kind, String value) {
	}

	public static List<Level> levels(JsonNode chain) {
		List<Level> levels = new ArrayList<>();
		if (chain != null && chain.isArray()) {
			for (JsonNode element : chain) {
				levels.add(new Level(text(element, "kind"), text(element, "value")));
			}
		}
		return levels;
	}

	public static int approvedCount(JsonNode approvals) {
		int count = 0;
		if (approvals != null && approvals.isArray()) {
			for (JsonNode element : approvals) {
				if ("approve".equals(text(element, "decision"))) {
					count++;
				}
			}
		}
		return count;
	}

	public static boolean hasActed(JsonNode approvals, String approver) {
		if (approvals != null && approvals.isArray()) {
			for (JsonNode element : approvals) {
				if (approver != null && approver.equals(text(element, "approver"))) {
					return true;
				}
			}
		}
		return false;
	}

	public static boolean matches(Level level, String approverIdentity, Collection<String> approverGroups) {
		if (level == null || level.value() == null) {
			return false;
		}
		if (KIND_EMAIL.equals(level.kind())) {
			return level.value().equals(approverIdentity);
		}
		if (KIND_OIDC_GROUP.equals(level.kind())) {
			return approverGroups != null && approverGroups.contains(level.value());
		}
		return false;
	}

	public static ArrayNode append(ObjectMapper objectMapper, JsonNode approvals, String approver, int level,
			String decision, String reason, Instant at) {
		ArrayNode array = objectMapper.createArrayNode();
		if (approvals != null && approvals.isArray()) {
			approvals.forEach(array::add);
		}
		ObjectNode entry = objectMapper.createObjectNode();
		entry.put("approver", approver);
		entry.put("level", level);
		entry.put("decision", decision);
		if (reason != null) {
			entry.put("reason", reason);
		}
		entry.put("at", at.toString());
		array.add(entry);
		return array;
	}

	private static String text(JsonNode node, String field) {
		JsonNode value = node == null ? null : node.get(field);
		return value != null && value.isString() ? value.stringValue() : null;
	}
}
