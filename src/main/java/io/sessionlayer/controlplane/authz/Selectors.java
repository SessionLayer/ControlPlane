package io.sessionlayer.controlplane.authz;

import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import tools.jackson.databind.JsonNode;

public final class Selectors {

	private Selectors() {
	}

	public static boolean identityMatches(JsonNode selector, String identity, Iterable<String> groups) {
		if (selector == null) {
			return false; // no subject named → selects no one
		}
		requireObject(selector, "identity_selector");
		JsonNode all = selector.get("all");
		if (all != null && all.isBoolean() && all.booleanValue()) {
			return true;
		}
		JsonNode identities = selector.get("identities");
		if (identity != null && identities != null && identities.isArray()) {
			for (JsonNode n : identities.values()) {
				if (identity.equals(text(n))) {
					return true;
				}
			}
		}
		JsonNode wantGroups = selector.get("groups");
		if (wantGroups != null && wantGroups.isArray()) {
			Set<String> want = new HashSet<>();
			for (JsonNode n : wantGroups.values()) {
				String t = text(n);
				if (t != null) {
					want.add(t);
				}
			}
			for (String g : groups) {
				if (want.contains(g)) {
					return true;
				}
			}
		}
		return false;
	}

	public static boolean labelMatches(JsonNode selector, Map<String, String> labels) {
		if (selector == null) {
			return true;
		}
		requireObject(selector, "node_label_selector");
		for (var entry : selector.properties()) {
			if (!keyMatches(entry.getValue(), labels.get(entry.getKey()))) {
				return false;
			}
		}
		return true;
	}

	private static boolean keyMatches(JsonNode condition, String labelValue) {
		if (condition.isArray()) {
			for (JsonNode c : condition.values()) {
				if (conditionMatches(c, labelValue)) {
					return true;
				}
			}
			return false;
		}
		return conditionMatches(condition, labelValue);
	}

	private static boolean conditionMatches(JsonNode condition, String labelValue) {
		requireObject(condition, "label condition");
		String op = text(condition.get("op"));
		if (op == null) {
			throw new IllegalArgumentException("label condition missing 'op'");
		}
		if (labelValue == null) {
			return false;
		}
		return switch (op) {
			case "eq" -> labelValue.equals(requireValue(condition));
			case "glob" -> Globs.matches(requireValue(condition), labelValue);
			case "regex" -> AnchoredRe2.matches(requireValue(condition), labelValue);
			case "in" -> valuesOf(condition).contains(labelValue);
			default -> throw new IllegalArgumentException("unknown label op: " + op);
		};
	}

	public static boolean sourceIpPasses(JsonNode condition, String sourceIp) {
		if (condition == null) {
			return true;
		}
		requireObject(condition, "source_ip_condition");
		Set<String> permit = cidrs(condition.get("permit_cidrs"));
		Set<String> deny = cidrs(condition.get("deny_cidrs"));
		if (permit.isEmpty() && deny.isEmpty()) {
			return true;
		}
		if (sourceIp == null || sourceIp.isBlank() || !Cidrs.isAddress(sourceIp)) {
			return false;
		}
		if (!permit.isEmpty() && permit.stream().noneMatch(c -> Cidrs.contains(c, sourceIp))) {
			return false;
		}
		return deny.stream().noneMatch(c -> Cidrs.contains(c, sourceIp));
	}

	private static Set<String> cidrs(JsonNode array) {
		Set<String> out = new HashSet<>();
		if (array != null && array.isArray()) {
			for (JsonNode n : array.values()) {
				String t = text(n);
				if (t != null) {
					out.add(t);
				}
			}
		}
		return out;
	}

	private static Set<String> valuesOf(JsonNode condition) {
		JsonNode values = condition.get("values");
		if (values == null || !values.isArray()) {
			throw new IllegalArgumentException("'in' condition requires a 'values' array");
		}
		Set<String> out = new HashSet<>();
		for (JsonNode n : values.values()) {
			String t = text(n);
			if (t != null) {
				out.add(t);
			}
		}
		return out;
	}

	private static String requireValue(JsonNode condition) {
		String value = text(condition.get("value"));
		if (value == null) {
			throw new IllegalArgumentException("label condition requires a 'value'");
		}
		return value;
	}

	static String text(JsonNode node) {
		return node != null && node.isString() ? node.stringValue() : null;
	}

	private static void requireObject(JsonNode node, String what) {
		if (!node.isObject()) {
			throw new IllegalArgumentException(what + " must be a JSON object");
		}
	}
}
