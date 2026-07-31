package io.sessionlayer.controlplane.web;

import io.sessionlayer.controlplane.api.model.LockTarget;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;
import tools.jackson.databind.node.ArrayNode;
import tools.jackson.databind.node.JsonNodeFactory;
import tools.jackson.databind.node.ObjectNode;

/**
 * Lock CRUD ingest validation. A lock is top-tier deny; malformed targets could
 * silently over- or under-block, so reject upfront.
 */
final class LockIngestValidation {

	private static final JsonNodeFactory JSON = JsonNodeFactory.instance;

	// Bounds so an oversize lock can't inflate the fleet-wide snapshot past a
	// Gateway's gRPC inbound cap and break resync (a self-DoS on the deny channel).
	private static final int MAX_FACET_ENTRIES = 256;
	private static final int MAX_TOTAL_ENTRIES = 1024;
	private static final int MAX_VALUE_LENGTH = 512;
	private static final int MAX_REASON_LENGTH = 4096;

	private LockIngestValidation() {
	}

	static void checkReason(String reason) {
		if (reason == null || reason.isBlank()) {
			throw invalid("a lock reason is required");
		}
		if (reason.length() > MAX_REASON_LENGTH) {
			throw invalid("reason must be at most " + MAX_REASON_LENGTH + " characters");
		}
	}

	static ObjectNode toSelector(LockTarget target) {
		if (target == null) {
			throw invalid("a lock target is required");
		}
		ObjectNode selector = JSON.objectNode();
		boolean any = false;
		any |= putStrings(selector, "identities", target.getIdentities(), "identities");
		any |= putStrings(selector, "groups", target.getGroups(), "groups");
		any |= putStrings(selector, "principals", target.getPrincipals(), "principals");
		any |= putLabels(selector, target.getNodeLabels());
		any |= putNodeIds(selector, target.getNodeIds());
		boolean all = Boolean.TRUE.equals(target.getAll());
		if (all) {
			selector.put("all", true);
		}
		if (!any && !all) {
			throw invalid("a lock target must name at least one facet, or set all:true for an intentional "
					+ "fleet-wide lock");
		}
		if (totalEntries(selector) > MAX_TOTAL_ENTRIES) {
			throw invalid("a lock target has too many entries (max " + MAX_TOTAL_ENTRIES + " across all facets)");
		}
		return selector;
	}

	private static int totalEntries(ObjectNode selector) {
		int total = 0;
		for (var entry : selector.properties()) {
			if (entry.getValue().isArray()) {
				total += entry.getValue().size();
			}
		}
		return total;
	}

	static Integer normalizeTtl(Long ttlSeconds) {
		if (ttlSeconds == null) {
			return null; // no expiry — the lock stands until released
		}
		if (ttlSeconds <= 0 || ttlSeconds > Integer.MAX_VALUE) {
			throw invalid("ttlSeconds must be a positive number of seconds");
		}
		return ttlSeconds.intValue();
	}

	/** A short, secret-free audit summary of the facets a lock targets. */
	static String summarize(ObjectNode selector) {
		return selector.properties().stream()
				.map(entry -> entry.getKey() + (entry.getValue().isArray() ? ":" + entry.getValue().size() : ""))
				.collect(Collectors.joining(","));
	}

	private static boolean putStrings(ObjectNode selector, String key, List<String> values, String facet) {
		if (values == null || values.isEmpty()) {
			return false;
		}
		checkFacetSize(values.size(), facet);
		ArrayNode array = JSON.arrayNode();
		for (String value : values) {
			if (value == null || value.isBlank()) {
				throw invalid("a " + facet + " entry must not be blank");
			}
			if (value.length() > MAX_VALUE_LENGTH) {
				throw invalid("a " + facet + " entry is too long (max " + MAX_VALUE_LENGTH + " characters)");
			}
			array.add(value.trim());
		}
		selector.set(key, array);
		return true;
	}

	private static boolean putLabels(ObjectNode selector, List<String> labels) {
		if (labels == null || labels.isEmpty()) {
			return false;
		}
		checkFacetSize(labels.size(), "nodeLabels");
		ArrayNode array = JSON.arrayNode();
		for (String label : labels) {
			if (label == null || label.isBlank()) {
				throw invalid("a nodeLabels entry must not be blank");
			}
			if (label.length() > MAX_VALUE_LENGTH) {
				throw invalid("a nodeLabels entry is too long (max " + MAX_VALUE_LENGTH + " characters)");
			}
			int eq = label.indexOf('=');
			if (eq <= 0) {
				throw invalid("a nodeLabels entry must be \"key=value\" with a non-blank key");
			}
			array.add(label.trim());
		}
		selector.set("node_labels", array);
		return true;
	}

	private static boolean putNodeIds(ObjectNode selector, List<UUID> nodeIds) {
		if (nodeIds == null || nodeIds.isEmpty()) {
			return false;
		}
		checkFacetSize(nodeIds.size(), "nodeIds");
		ArrayNode array = JSON.arrayNode();
		for (UUID nodeId : nodeIds) {
			if (nodeId == null) {
				throw invalid("a nodeIds entry must be a valid UUID");
			}
			array.add(nodeId.toString());
		}
		selector.set("node_ids", array);
		return true;
	}

	private static void checkFacetSize(int size, String facet) {
		if (size > MAX_FACET_ENTRIES) {
			throw invalid("the " + facet + " facet has too many entries (max " + MAX_FACET_ENTRIES + ")");
		}
	}

	private static LockValidationException invalid(String message) {
		return new LockValidationException(message);
	}
}
