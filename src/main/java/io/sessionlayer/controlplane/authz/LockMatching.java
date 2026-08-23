package io.sessionlayer.controlplane.authz;

import java.util.Map;
import java.util.Set;
import tools.jackson.databind.JsonNode;

public final class LockMatching {

	private LockMatching() {
	}

	public record LockSubject(String identity, String nodeId, Map<String, String> labels, Set<String> allowedLogins,
			String requestedPrincipal, Set<String> groups) {
	}

	public static boolean matches(JsonNode target, LockSubject subject) {
		if (target == null || !target.isObject() || target.isEmpty()) {
			return true; // uninterpretable/empty → fail closed (lock applies)
		}
		boolean recognized = false;

		if (target.has("all")) {
			recognized = true;
			if (target.get("all").asBoolean(false)) {
				return true;
			}
		}
		if (target.has("identity")) {
			recognized = true;
			if (equalsNonNull(Selectors.text(target.get("identity")), subject.identity())) {
				return true;
			}
		}
		if (target.has("identities")) {
			recognized = true;
			if (containsText(target.get("identities"), subject.identity())) {
				return true;
			}
		}
		if (target.has("group")) {
			recognized = true;
			if (subject.groups().contains(Selectors.text(target.get("group")))) {
				return true;
			}
		}
		if (target.has("groups")) {
			recognized = true;
			if (anyIn(target.get("groups"), subject.groups())) {
				return true;
			}
		}
		if (target.has("node_id")) {
			recognized = true;
			if (equalsNonNull(Selectors.text(target.get("node_id")), subject.nodeId())) {
				return true;
			}
		}
		if (target.has("node_ids")) {
			recognized = true;
			if (containsText(target.get("node_ids"), subject.nodeId())) {
				return true;
			}
		}
		if (target.has("principal")) {
			recognized = true;
			if (principalLocked(Selectors.text(target.get("principal")), subject)) {
				return true;
			}
		}
		if (target.has("principals")) {
			recognized = true;
			if (anyPrincipalLocked(target.get("principals"), subject)) {
				return true;
			}
		}
		if (target.has("node_label")) {
			recognized = true;
			if (labelLocked(target.get("node_label"), subject.labels())) {
				return true;
			}
		}
		if (target.has("node_labels")) {
			recognized = true;
			if (anyLabelLocked(target.get("node_labels"), subject.labels())) {
				return true;
			}
		}
		// An object with no facet we understand could be meant to lock this connect;
		// fail closed rather than silently ignore it.
		return !recognized;
	}

	private static boolean principalLocked(String locked, LockSubject subject) {
		if (locked == null) {
			return false;
		}
		return locked.equals(subject.requestedPrincipal()) || subject.allowedLogins().contains(locked);
	}

	private static boolean anyPrincipalLocked(JsonNode array, LockSubject subject) {
		if (array == null || !array.isArray()) {
			return false;
		}
		for (JsonNode element : array) {
			if (principalLocked(Selectors.text(element), subject)) {
				return true;
			}
		}
		return false;
	}

	private static boolean labelLocked(JsonNode nodeLabel, Map<String, String> labels) {
		if (nodeLabel == null || !nodeLabel.isObject()) {
			return true;
		}
		String key = Selectors.text(nodeLabel.get("key"));
		String value = Selectors.text(nodeLabel.get("value"));
		if (key == null || value == null) {
			return true;
		}
		return value.equals(labels.get(key));
	}

	private static boolean anyLabelLocked(JsonNode array, Map<String, String> labels) {
		if (array == null || !array.isArray()) {
			return false;
		}
		for (JsonNode element : array) {
			String token = Selectors.text(element);
			if (token == null) {
				continue;
			}
			int eq = token.indexOf('=');
			if (eq < 0) {
				return true;
			}
			if (token.substring(eq + 1).equals(labels.get(token.substring(0, eq)))) {
				return true;
			}
		}
		return false;
	}

	private static boolean containsText(JsonNode array, String value) {
		if (value == null || array == null || !array.isArray()) {
			return false;
		}
		for (JsonNode element : array) {
			if (value.equals(Selectors.text(element))) {
				return true;
			}
		}
		return false;
	}

	private static boolean anyIn(JsonNode array, Set<String> values) {
		if (array == null || !array.isArray()) {
			return false;
		}
		for (JsonNode element : array) {
			if (values.contains(Selectors.text(element))) {
				return true;
			}
		}
		return false;
	}

	private static boolean equalsNonNull(String a, String b) {
		return a != null && a.equals(b);
	}
}
