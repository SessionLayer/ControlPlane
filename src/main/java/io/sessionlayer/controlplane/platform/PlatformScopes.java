package io.sessionlayer.controlplane.platform;

import java.time.Instant;
import tools.jackson.databind.JsonNode;

public final class PlatformScopes {

	private PlatformScopes() {
	}

	public static boolean covers(JsonNode scope, PlatformScope request) {
		if (scope == null || scope.isNull() || scope.isEmpty()) {
			return true;
		}
		if (!scope.isObject() || request == null) {
			return false;
		}
		// Degenerate facets impose no constraint (fail closed). Must mirror
		// AuditSearchSql
		// predicate so search filter and single-event check never diverge.
		boolean anyConstraint = false;
		JsonNode nodeLabels = scope.get("node_labels");
		if (nodeLabels != null && nodeLabels.isObject() && !nodeLabels.isEmpty()) {
			anyConstraint = true;
			if (!nodeLabelsCover(nodeLabels, request)) {
				return false;
			}
		}
		JsonNode users = scope.get("users");
		if (users != null && users.isArray() && !users.isEmpty()) {
			anyConstraint = true;
			if (!usersCover(users, request)) {
				return false;
			}
		}
		JsonNode time = scope.get("time");
		if (time != null && time.isObject() && (time.has("not_before") || time.has("not_after"))) {
			anyConstraint = true;
			if (!timeCovers(time, request)) {
				return false;
			}
		}
		return anyConstraint;
	}

	public static boolean isValid(JsonNode scope) {
		if (scope == null || scope.isNull() || scope.isEmpty()) {
			return true;
		}
		if (!scope.isObject()) {
			return false;
		}
		JsonNode nodeLabels = scope.get("node_labels");
		if (nodeLabels != null && nodeLabels.isObject() && !nodeLabels.isEmpty()) {
			return true;
		}
		JsonNode users = scope.get("users");
		if (users != null && users.isArray() && !users.isEmpty()) {
			return true;
		}
		JsonNode time = scope.get("time");
		return time != null && time.isObject() && (time.has("not_before") || time.has("not_after"));
	}

	private static boolean nodeLabelsCover(JsonNode nodeLabels, PlatformScope request) {
		if (nodeLabels == null || !nodeLabels.isObject()) {
			return true;
		}
		for (var entry : nodeLabels.properties()) {
			String want = text(entry.getValue());
			if (want == null || !want.equals(request.nodeLabels().get(entry.getKey()))) {
				return false;
			}
		}
		return true;
	}

	private static boolean usersCover(JsonNode users, PlatformScope request) {
		if (users == null || !users.isArray()) {
			return true;
		}
		for (JsonNode u : users.values()) {
			if (u.isString() && u.stringValue().equals(request.user())) {
				return true;
			}
		}
		return false;
	}

	private static boolean timeCovers(JsonNode time, PlatformScope request) {
		if (time == null || !time.isObject()) {
			return true;
		}
		Instant at = request.at();
		if (at == null) {
			return false; // a time-windowed binding cannot cover an unspecified time
		}
		String notBefore = text(time.get("not_before"));
		String notAfter = text(time.get("not_after"));
		if (notBefore != null && at.isBefore(Instant.parse(notBefore))) {
			return false;
		}
		return notAfter == null || !at.isAfter(Instant.parse(notAfter));
	}

	private static String text(JsonNode node) {
		return node != null && node.isString() ? node.stringValue() : null;
	}
}
