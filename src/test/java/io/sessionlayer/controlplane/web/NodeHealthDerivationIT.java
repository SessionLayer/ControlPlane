package io.sessionlayer.controlplane.web;

import static org.assertj.core.api.Assertions.assertThat;

import io.sessionlayer.controlplane.data.config.PlatformRole;
import io.sessionlayer.controlplane.data.config.PlatformRoleRepository;
import io.sessionlayer.controlplane.data.config.RoleBinding;
import io.sessionlayer.controlplane.data.config.RoleBindingRepository;
import io.sessionlayer.controlplane.data.config.ServiceAccount;
import io.sessionlayer.controlplane.data.config.ServiceAccountRepository;
import io.sessionlayer.controlplane.data.runtime.Node;
import io.sessionlayer.controlplane.data.runtime.NodeRepository;
import io.sessionlayer.controlplane.data.runtime.Presence;
import io.sessionlayer.controlplane.data.runtime.PresenceRepository;
import io.sessionlayer.controlplane.machine.MachineIdentityService;
import io.sessionlayer.controlplane.platform.PlatformPermissions;
import io.sessionlayer.controlplane.support.AbstractAuthIT;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webtestclient.autoconfigure.AutoConfigureWebTestClient;
import org.springframework.http.MediaType;
import org.springframework.r2dbc.core.DatabaseClient;
import org.springframework.test.web.reactive.server.WebTestClient;
import tools.jackson.databind.node.JsonNodeFactory;

/**
 * {@code health} and {@code owningGateway} are derived at read time. Every
 * assertion here is on the VALUE: a regression that stops populating them reads
 * as {@code unknown} again and fails.
 */
@AutoConfigureWebTestClient
class NodeHealthDerivationIT extends AbstractAuthIT {

	private static final JsonNodeFactory JSON = JsonNodeFactory.instance;
	private static final SecureRandom RANDOM = new SecureRandom();

	@Autowired
	WebTestClient client;
	@Autowired
	MachineIdentityService machineIdentity;
	@Autowired
	ServiceAccountRepository serviceAccounts;
	@Autowired
	PlatformRoleRepository roles;
	@Autowired
	RoleBindingRepository bindings;
	@Autowired
	NodeRepository nodes;
	@Autowired
	PresenceRepository presences;
	@Autowired
	DatabaseClient db;

	@Test
	void anAgentNodesHealthAndOwnerFollowItsPresenceClaim() {
		String token = tokenWith("svc-node-health-" + unique(), PlatformPermissions.NODE_ENROLL);
		String name = "agent-" + unique();
		UUID id = registerAgent(token, name);

		getNode(token, id).jsonPath("$.health").isEqualTo("unknown").jsonPath("$.owningGateway").doesNotExist();

		String owner = "gw-health-" + unique();
		claim(id, owner, Instant.now());

		getNode(token, id).jsonPath("$.health").isEqualTo("healthy").jsonPath("$.owningGateway").isEqualTo(owner);
		assertThat(listNode(token, id)).containsEntry("health", "healthy").containsEntry("owningGateway", owner);

		ageClaimPastTheWindow(id);

		// A stale claim means no live Gateway holds the channel: the node is
		// unreachable and naming its last owner would point routing at a dead path.
		getNode(token, id).jsonPath("$.health").isEqualTo("unreachable").jsonPath("$.owningGateway").doesNotExist();
	}

	@Test
	void aNodeWithNoHostAnchorIsUnhealthy() {
		String token = tokenWith("svc-node-anchorless-" + unique(), PlatformPermissions.NODE_ENROLL);
		// Exactly what an Agent join auto-creates for a name nobody registered: an
		// active node with no host anchor. The Gateway never TOFUs, so every session to
		// it aborts - enrolled, but unusable.
		Node node = nodes.save(Node.create("agent-" + unique(), null, JSON.objectNode(), "agent", "active", null))
				.block();

		getNode(token, node.id()).jsonPath("$.health").isEqualTo("unhealthy").jsonPath("$.owningGateway")
				.doesNotExist();

		// Unusable outranks unreachable: a fresh owner does not make an anchorless node
		// connectable. But the owner is still REPORTED, because the two fields answer
		// different questions and routing attaches that same owner with no anchor
		// precondition - an API that said nobody owned the node would contradict the
		// Gateway the session is actually routed to. `unhealthy` with an owner is also
		// the most useful thing an operator can be told here: the Agent is connected,
		// and nobody ever anchored the node.
		String owner = "gw-anchorless-" + unique();
		claim(node.id(), owner, Instant.now());
		getNode(token, node.id()).jsonPath("$.health").isEqualTo("unhealthy").jsonPath("$.owningGateway")
				.isEqualTo(owner);

		ageClaimPastTheWindow(node.id());
		getNode(token, node.id()).jsonPath("$.health").isEqualTo("unhealthy").jsonPath("$.owningGateway")
				.doesNotExist();
	}

	@Test
	void anAgentlessNodeIsAlwaysUnknown() {
		String token = tokenWith("svc-node-agentless-" + unique(), PlatformPermissions.NODE_ENROLL);
		UUID id = registerAgentless(token, "host-" + unique());

		// Deliberate, and the documentation says so: the CP dials an agentless node on
		// demand and runs no probe, so it holds no continuous liveness signal. Even a
		// presence row (which nothing writes for this connector) must not be read as
		// one - ownership is an agent-model concept and any Gateway can dial.
		getNode(token, id).jsonPath("$.health").isEqualTo("unknown").jsonPath("$.owningGateway").doesNotExist();
		claim(id, "gw-agentless-" + unique(), Instant.now());
		getNode(token, id).jsonPath("$.health").isEqualTo("unknown").jsonPath("$.owningGateway").doesNotExist();
	}

	private void claim(UUID nodeId, String owningGateway, Instant lastSeen) {
		presences.save(Presence.create(nodeId, owningGateway, "10.9.0.1:7000", 1L, UUID.randomUUID(), lastSeen))
				.block();
	}

	private void ageClaimPastTheWindow(UUID nodeId) {
		Long updated = db.sql("UPDATE runtime.presence SET last_seen = now() - interval '1 hour' WHERE node_id = :id")
				.bind("id", nodeId).fetch().rowsUpdated().block();
		assertThat(updated).isEqualTo(1L);
	}

	private WebTestClient.BodyContentSpec getNode(String token, UUID id) {
		return client.get().uri("/v1/nodes/" + id).header("Authorization", "Bearer " + token).exchange().expectStatus()
				.isOk().expectBody();
	}

	@SuppressWarnings("unchecked")
	private Map<String, Object> listNode(String token, UUID id) {
		Map<?, ?> body = client.get().uri("/v1/nodes").header("Authorization", "Bearer " + token).exchange()
				.expectStatus().isOk().expectBody(Map.class).returnResult().getResponseBody();
		List<Map<String, Object>> listed = (List<Map<String, Object>>) body.get("nodes");
		return listed.stream().filter(node -> id.toString().equals(node.get("id"))).findFirst().orElseThrow();
	}

	private UUID registerAgent(String token, String name) {
		return register(token, Map.of("name", name, "connectorKind", "agent", "pinnedHostKey", pinnedHostKeyLine()));
	}

	private UUID registerAgentless(String token, String name) {
		return register(token, Map.of("name", name, "address", "10.0.0.5:22", "pinnedHostKey", pinnedHostKeyLine()));
	}

	private UUID register(String token, Map<String, Object> body) {
		Map<?, ?> created = client.post().uri("/v1/nodes").header("Authorization", "Bearer " + token)
				.contentType(MediaType.APPLICATION_JSON).bodyValue(body).exchange().expectStatus().isCreated()
				.expectBody(Map.class).returnResult().getResponseBody();
		return UUID.fromString(created.get("id").toString());
	}

	private static String pinnedHostKeyLine() {
		byte[] blob = new byte[48];
		RANDOM.nextBytes(blob);
		return "ecdsa-sha2-nistp256 " + Base64.getEncoder().encodeToString(blob) + " host@example";
	}

	private String tokenWith(String saName, String... permissions) {
		ServiceAccount sa = serviceAccounts
				.save(ServiceAccount.create(saName, "test", "client_secret", null, null, "api")).block();
		var issued = machineIdentity.issueCredential(sa.id(), "client_secret", null, null, null, null, "admin").block();
		PlatformRole role = roles.save(
				PlatformRole.create("node-health-role-" + UUID.randomUUID(), List.of(permissions), "test", "default"))
				.block();
		bindings.save(RoleBinding.create(role.id(), "user", saName, null, "default")).block();
		var token = machineIdentity.issueToken(new MachineIdentityService.TokenRequest("client_credentials", saName,
				null, null, issued.clientSecret(), null), null, "203.0.113.30").block();
		return token.accessToken();
	}

	private static String unique() {
		return UUID.randomUUID().toString().substring(0, 8);
	}
}
