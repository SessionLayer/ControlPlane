package io.sessionlayer.controlplane.configapi;

import io.sessionlayer.controlplane.authz.Selectors;
import io.sessionlayer.controlplane.web.ApiProblemException;
import java.util.List;
import java.util.Map;
import tools.jackson.databind.JsonNode;

final class SelectorValidation {

	private SelectorValidation() {
	}

	static void identitySelector(JsonNode selector) {
		if (selector == null) {
			return;
		}
		try {
			Selectors.identityMatches(selector, "validate", List.of());
		} catch (RuntimeException bad) {
			throw ApiProblemException.validation("identitySelector is not a valid selector: " + bad.getMessage());
		}
	}

	static void labelSelector(JsonNode selector, String field) {
		if (selector == null) {
			return;
		}
		try {
			Selectors.labelMatches(selector, Map.of());
		} catch (RuntimeException bad) {
			throw ApiProblemException.validation(field + " is not a valid node-label selector: " + bad.getMessage());
		}
	}

	static void sourceIpCondition(JsonNode condition) {
		if (condition == null) {
			return;
		}
		try {
			Selectors.sourceIpPasses(condition, "127.0.0.1");
		} catch (RuntimeException bad) {
			throw ApiProblemException.validation("sourceIpCondition is not a valid condition: " + bad.getMessage());
		}
	}
}
