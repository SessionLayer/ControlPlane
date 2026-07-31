package io.sessionlayer.controlplane.authz;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import tools.jackson.databind.node.ArrayNode;
import tools.jackson.databind.node.JsonNodeFactory;
import tools.jackson.databind.node.ObjectNode;

class SelectorsTest {

	private static final JsonNodeFactory JSON = JsonNodeFactory.instance;

	@Test
	void identityByNameGroupOrAll() {
		assertThat(Selectors.identityMatches(AuthzFixtures.identity("alice"), "alice", List.of())).isTrue();
		assertThat(Selectors.identityMatches(AuthzFixtures.identity("alice"), "bob", List.of())).isFalse();
		assertThat(Selectors.identityMatches(AuthzFixtures.groups("admins"), "bob", List.of("admins"))).isTrue();
		assertThat(Selectors.identityMatches(AuthzFixtures.groups("admins"), "bob", List.of("devs"))).isFalse();
		assertThat(Selectors.identityMatches(AuthzFixtures.identityAll(), "anyone", List.of())).isTrue();
		assertThat(Selectors.identityMatches(null, "alice", List.of())).isFalse();
	}

	@Test
	void labelAndAcrossKeysOrWithinAKey() {
		Map<String, String> labels = Map.of("env", "prod", "tier", "web");
		ObjectNode both = JSON.objectNode();
		both.set("env", JSON.objectNode().put("op", "eq").put("value", "prod"));
		both.set("tier", JSON.objectNode().put("op", "eq").put("value", "web"));
		assertThat(Selectors.labelMatches(both, labels)).isTrue();

		ObjectNode mismatch = JSON.objectNode();
		mismatch.set("env", JSON.objectNode().put("op", "eq").put("value", "prod"));
		mismatch.set("tier", JSON.objectNode().put("op", "eq").put("value", "db"));
		assertThat(Selectors.labelMatches(mismatch, labels)).isFalse();

		ArrayNode either = JSON.arrayNode();
		either.add(JSON.objectNode().put("op", "eq").put("value", "staging"));
		either.add(JSON.objectNode().put("op", "eq").put("value", "prod"));
		ObjectNode orKey = JSON.objectNode();
		orKey.set("env", either);
		assertThat(Selectors.labelMatches(orKey, labels)).isTrue();

		assertThat(Selectors.labelMatches(null, labels)).isTrue();
		assertThat(Selectors.labelMatches(AuthzFixtures.labelEq("region", "eu"), labels)).isFalse();
	}

	@Test
	void sourceIpIsADenyOnlyReducer() {
		assertThat(Selectors.sourceIpPasses(AuthzFixtures.sourceDeny("10.0.0.0/8"), "10.1.2.3")).isFalse();
		assertThat(Selectors.sourceIpPasses(AuthzFixtures.sourceDeny("10.0.0.0/8"), "192.168.1.1")).isTrue();
		assertThat(Selectors.sourceIpPasses(AuthzFixtures.sourcePermit("10.0.0.0/8"), "10.1.2.3")).isTrue();
		assertThat(Selectors.sourceIpPasses(AuthzFixtures.sourcePermit("10.0.0.0/8"), "192.168.1.1")).isFalse();
		assertThat(Selectors.sourceIpPasses(AuthzFixtures.sourceDeny("10.0.0.0/8"), null)).isFalse();
		assertThat(Selectors.sourceIpPasses(AuthzFixtures.sourcePermit("10.0.0.0/8"), null)).isFalse();
		assertThat(Selectors.sourceIpPasses(null, null)).isTrue();
	}
}
