package io.sessionlayer.controlplane.web;

import static org.assertj.core.api.Assertions.assertThat;

import io.sessionlayer.controlplane.authz.ConnectAuthorizationService;
import io.sessionlayer.controlplane.authz.ConnectDecision;
import io.sessionlayer.controlplane.authz.NodeConnectionInfo;
import io.sessionlayer.controlplane.ca.mtls.InternalMtlsCaService;
import io.sessionlayer.controlplane.data.config.DpRule;
import io.sessionlayer.controlplane.data.config.DpRuleRepository;
import io.sessionlayer.controlplane.data.config.PlatformRole;
import io.sessionlayer.controlplane.data.config.PlatformRoleRepository;
import io.sessionlayer.controlplane.data.config.RoleBinding;
import io.sessionlayer.controlplane.data.config.RoleBindingRepository;
import io.sessionlayer.controlplane.data.config.ServiceAccount;
import io.sessionlayer.controlplane.data.config.ServiceAccountRepository;
import io.sessionlayer.controlplane.data.runtime.GatewayIdentity;
import io.sessionlayer.controlplane.data.runtime.GatewayIdentityRepository;
import io.sessionlayer.controlplane.machine.MachineIdentityService;
import io.sessionlayer.controlplane.platform.PlatformPermissions;
import io.sessionlayer.controlplane.support.AbstractAuthIT;
import java.security.SecureRandom;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webtestclient.autoconfigure.AutoConfigureWebTestClient;
import org.springframework.http.MediaType;
import org.springframework.test.web.reactive.server.WebTestClient;
import tools.jackson.databind.node.JsonNodeFactory;
import tools.jackson.databind.node.ObjectNode;

/**
 * An agent-connected node's host identity is anchored at REGISTRATION, before
 * the Agent joins (§9.3; FR-CONN-5/7). The Gateway runs the same no-TOFU
 * verification on the inner leg whichever connector reached the node, so an
 * anchorless agent node aborts every session — which is why the anchor must be
 * writable through the API and must reach the Gateway in the authorizer's
 * answer, not merely exist as a row.
 */
@AutoConfigureWebTestClient
class AgentNodeHostAnchorIT extends AbstractAuthIT {

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
	GatewayIdentityRepository gatewayIdentities;
	@Autowired
	DpRuleRepository dpRules;
	@Autowired
	ConnectAuthorizationService connectAuthorization;
	@Autowired
	InternalMtlsCaService mtlsCa;

	@Test
	void anApiRegisteredAgentNodesPinnedKeyReachesTheGatewayAsHostVerificationMaterial() {
		String token = tokenWith("svc-agent-anchor-" + unique(), PlatformPermissions.NODE_ENROLL);
		String pinnedLine = pinnedHostKeyLine();

		Map<?, ?> created = client.post().uri("/v1/nodes").header("Authorization", "Bearer " + token)
				.contentType(MediaType.APPLICATION_JSON)
				.bodyValue(Map.of("name", "agent-" + unique(), "connectorKind", "agent", "labels",
						Map.of("env", "prod"), "pinnedHostKey", pinnedLine))
				.exchange().expectStatus().isCreated().expectBody(Map.class).returnResult().getResponseBody();
		assertThat(created.get("connectorKind")).isEqualTo("agent");
		assertThat(created.get("address")).isNull();

		String identity = "alice-" + unique();
		seedAllow(identity, List.of("deploy"), List.of("shell"));
		GatewayIdentity gateway = seedGateway();

		ConnectDecision decision = connectAuthorization.authorize(gateway.id(), gateway.fingerprint(), identity,
				List.of(), UUID.fromString(created.get("id").toString()), null, "deploy", "10.0.0.5", UUID.randomUUID(),
				null).block();

		assertThat(decision.allowed()).isTrue();
		NodeConnectionInfo connection = decision.nodeConnection();
		assertThat(connection.connectorKind()).isEqualTo(NodeConnectionInfo.ConnectorModel.OUTBOUND_AGENT);
		// The Agent dials out; a dial address on an agent node would be a lie the
		// authorizer hands the data plane.
		assertThat(connection.dialAddress()).isEmpty();
		// The outcome the gap is about: without this the Gateway's HostVerifier holds
		// an empty trust set and aborts the inner leg (no TOFU), agent node or not.
		assertThat(connection.hasHostVerification()).isTrue();
		assertThat(connection.pinnedHostKeys()).singleElement().isEqualTo(wireBlobOf(pinnedLine));
	}

	private void seedAllow(String identity, List<String> principals, List<String> capabilities) {
		ObjectNode identitySelector = JSON.objectNode();
		identitySelector.set("identities", JSON.arrayNode().add(identity));
		ObjectNode labelSelector = JSON.objectNode();
		labelSelector.set("env", JSON.objectNode().put("op", "eq").put("value", "prod"));
		dpRules.save(DpRule.create("rule-" + unique(), identitySelector, labelSelector, null, principals, 3600,
				capabilities, "allow", "api")).block();
	}

	// The allow path signs the decision context with a leaf off the internal mTLS
	// CA, which the gRPC server provisions at startup; this context runs without
	// it.
	private GatewayIdentity seedGateway() {
		mtlsCa.loadOrProvision("local").block();
		String fingerprint = "SHA256:" + UUID.randomUUID();
		return gatewayIdentities.save(GatewayIdentity.create("gw-" + unique(), "mtls:" + UUID.randomUUID(), fingerprint,
				0, "token", "active", Instant.now(), Instant.now().plus(24, ChronoUnit.HOURS))).block();
	}

	private static byte[] wireBlobOf(String openSshLine) {
		return Base64.getDecoder().decode(openSshLine.trim().split("\\s+")[1]);
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
				PlatformRole.create("agent-anchor-role-" + UUID.randomUUID(), List.of(permissions), "test", "default"))
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
