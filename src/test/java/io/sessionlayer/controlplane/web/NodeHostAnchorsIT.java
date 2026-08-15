package io.sessionlayer.controlplane.web;

import static org.assertj.core.api.Assertions.assertThat;

import io.sessionlayer.controlplane.data.config.PlatformRole;
import io.sessionlayer.controlplane.data.config.PlatformRoleRepository;
import io.sessionlayer.controlplane.data.config.RoleBinding;
import io.sessionlayer.controlplane.data.config.RoleBindingRepository;
import io.sessionlayer.controlplane.data.config.ServiceAccount;
import io.sessionlayer.controlplane.data.config.ServiceAccountRepository;
import io.sessionlayer.controlplane.data.runtime.AuditEvent;
import io.sessionlayer.controlplane.data.runtime.AuditEventRepository;
import io.sessionlayer.controlplane.data.runtime.Node;
import io.sessionlayer.controlplane.data.runtime.NodeRepository;
import io.sessionlayer.controlplane.machine.MachineIdentityService;
import io.sessionlayer.controlplane.platform.PlatformPermissions;
import io.sessionlayer.controlplane.support.AbstractAuthIT;
import java.security.SecureRandom;
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

/**
 * The host-anchor read/replace API. Two separate defects meet here: an
 * Agent-created node has no anchor and nothing could add one (so every session
 * to it aborted, permanently), and a host certificate — the anchor the
 * documentation calls primary — could not be stored at all, because
 * {@code node_host_key} was shaped for the pinned-key case and applied to both.
 */
@AutoConfigureWebTestClient
class NodeHostAnchorsIT extends AbstractAuthIT {

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
	AuditEventRepository auditEvents;
	@Autowired
	NodeRepository nodes;

	@Test
	void anAgentCreatedNodeIsUnhealthyUntilAnAnchorIsPutAndThenIsNot() {
		String admin = "svc-anchor-repair-" + unique();
		String token = tokenWith(admin, PlatformPermissions.NODE_ENROLL);
		// Exactly what AgentEnrollmentService.resolveNode writes when an Agent joins a
		// name nobody registered: active, agent-connected, no anchor. Until this API
		// existed the only escape was to abandon the name.
		Node node = nodes.save(Node.create("agent-" + unique(), null, JSON.objectNode(), "agent", "active", null))
				.block();

		assertThat(health(token, node.id())).isEqualTo("unhealthy");
		assertThat(anchors(token, node.id())).isEmpty();

		String pinned = pinnedHostKeyLine();
		Map<?, ?> replaced = putAnchors(token, node.id(), Map.of("pinnedHostKey", pinned)).expectStatus().isOk()
				.expectBody(Map.class).returnResult().getResponseBody();
		assertThat(replaced.get("nodeId")).isEqualTo(node.id().toString());

		List<Map<String, Object>> readBack = anchors(token, node.id());
		assertThat(readBack).singleElement().satisfies(anchor -> {
			assertThat(anchor.get("source")).isEqualTo("pinned_key");
			assertThat(anchor.get("keyType")).isEqualTo("ecdsa-sha2-nistp256");
			assertThat(anchor.get("fingerprint")).asString().startsWith("SHA256:");
			assertThat(anchor.get("recordedAt")).isNotNull();
		});
		// The repair is real, not cosmetic: the node leaves the state in which the
		// Gateway aborts every session to it.
		assertThat(health(token, node.id())).isEqualTo("unknown");
		assertThat(auditEvents.findByActor(admin).collectList().block())
				.anySatisfy(event -> assertThat(event.action()).isEqualTo("node.host_anchors.replace"));
	}

	@Test
	void replaceIsAWholeSetSwapSoARekeyedNodeStopsTrustingTheOldKey() throws Exception {
		String token = tokenWith("svc-anchor-rotate-" + unique(), PlatformPermissions.NODE_ENROLL);
		String first = pinnedHostKeyLine();
		UUID id = registerAgentless(token, Map.of("pinnedHostKey", first));

		String rotated = pinnedHostKeyLine();
		putAnchors(token, id, Map.of("pinnedHostKey", rotated)).expectStatus().isOk();

		// The superseded key is gone, not merely joined by its replacement — a rotation
		// that left the old anchor in place would keep trusting a key the node no
		// longer presents.
		List<String> fingerprints = anchors(token, id).stream().map(anchor -> (String) anchor.get("fingerprint"))
				.toList();
		assertThat(fingerprints).singleElement().isEqualTo(fingerprintOf(rotated));
		assertThat(fingerprints).doesNotContain(fingerprintOf(first));
	}

	@Test
	void aHostCertificateIsStorableAtRegistrationForBothConnectorKinds() {
		String token = tokenWith("svc-anchor-cert-" + unique(), PlatformPermissions.NODE_ENROLL);

		UUID agentless = registerAgentless(token, Map.of("hostCertificate", hostCertificateLine()));
		UUID agent = register(token, Map.of("name", "agent-" + unique(), "connectorKind", "agent", "hostCertificate",
				hostCertificateLine()));

		for (UUID id : List.of(agentless, agent)) {
			assertThat(anchors(token, id)).singleElement().satisfies(anchor -> {
				assertThat(anchor.get("source")).isEqualTo("host_ca");
				assertThat(anchor.get("keyType")).isEqualTo("ssh-ed25519-cert-v01@openssh.com");
				// Absent by construction: a certificate anchor's trust is the CA signature,
				// not a fingerprint comparison, and a manufactured one would never match
				// what the node reports.
				assertThat(anchor).doesNotContainKey("fingerprint");
			});
			// A certificate-only node is anchored, so it is not the unusable one.
			assertThat(health(token, id)).isNotEqualTo("unhealthy");
		}
	}

	@Test
	void bothAnchorsMayBeRecordedTogether() {
		String token = tokenWith("svc-anchor-both-" + unique(), PlatformPermissions.NODE_ENROLL);
		UUID id = registerAgentless(token,
				Map.of("hostCertificate", hostCertificateLine(), "pinnedHostKey", pinnedHostKeyLine()));

		// host_ca first: the primary path reads before the fallback.
		assertThat(anchors(token, id)).hasSize(2).extracting(anchor -> anchor.get("source")).containsExactly("host_ca",
				"pinned_key");

		// And the same pair goes in through the replace path, which writes the same
		// rows through the same validator.
		putAnchors(token, id, Map.of("hostCertificate", hostCertificateLine())).expectStatus().isOk();
		assertThat(anchors(token, id)).singleElement()
				.satisfies(anchor -> assertThat(anchor.get("source")).isEqualTo("host_ca"));
	}

	// sshd generates an RSA host key by default and the admin guide names
	// /etc/ssh/ssh_host_rsa_key.pub, so this is the line an operator is most likely
	// to paste. The original key_type CHECK listed rsa-sha2-256/512 — signature
	// algorithm names — and not ssh-rsa, so pasting it produced the same unhandled
	// insert failure as the certificate path.
	@Test
	void anRsaHostKeyAndAnRsaCertificateAreBothStorable() {
		String token = tokenWith("svc-anchor-rsa-" + unique(), PlatformPermissions.NODE_ENROLL);

		UUID pinned = registerAgentless(token, Map.of("pinnedHostKey", "ssh-rsa " + randomBlob(270) + " host@rsa"));
		assertThat(anchors(token, pinned)).singleElement()
				.satisfies(anchor -> assertThat(anchor.get("keyType")).isEqualTo("ssh-rsa"));

		UUID certified = registerAgentless(token,
				Map.of("hostCertificate", "ssh-rsa-cert-v01@openssh.com " + randomBlob(400) + " host@rsa"));
		assertThat(anchors(token, certified)).singleElement()
				.satisfies(anchor -> assertThat(anchor.get("keyType")).isEqualTo("ssh-rsa-cert-v01@openssh.com"));

		// And through the replace path, which writes the same rows.
		putAnchors(token, pinned, Map.of("pinnedHostKey", "ssh-rsa " + randomBlob(270) + " rotated@rsa")).expectStatus()
				.isOk();
	}

	// The line SHAPE is all badHostLine can check, so a well-formed line naming a
	// type the schema does not accept reaches the insert. That used to surface as a
	// 500 quoting the column and constraint; it is now the endpoint's own declared
	// refusal, and no input to either route produces a 500.
	@Test
	void anUnacceptableKeyTypeIsRefusedRatherThanFailingTheRequest() {
		String token = tokenWith("svc-anchor-type-" + unique(), PlatformPermissions.NODE_ENROLL);
		String unknownType = "ssh-dss " + randomBlob(48) + " host@legacy";

		client.post().uri("/v1/nodes").header("Authorization", "Bearer " + token)
				.contentType(MediaType.APPLICATION_JSON)
				.bodyValue(Map.of("name", "host-" + unique(), "address", "10.0.0.5:22", "pinnedHostKey", unknownType))
				.exchange().expectStatus().isBadRequest().expectHeader()
				.contentTypeCompatibleWith(MediaType.APPLICATION_PROBLEM_JSON).expectBody().jsonPath("$.title")
				.isEqualTo("Node request rejected");

		UUID id = registerAgentless(token, Map.of("pinnedHostKey", pinnedHostKeyLine()));
		putAnchors(token, id, Map.of("pinnedHostKey", unknownType)).expectStatus().isEqualTo(422).expectHeader()
				.contentTypeCompatibleWith(MediaType.APPLICATION_PROBLEM_JSON);
		// The refused replace rolled back: the node keeps the anchor it had.
		assertThat(anchors(token, id)).hasSize(1);
	}

	@Test
	void anEmptyOrMalformedAnchorSetIsRefused() {
		String token = tokenWith("svc-anchor-bad-" + unique(), PlatformPermissions.NODE_ENROLL);
		UUID id = registerAgentless(token, Map.of("pinnedHostKey", pinnedHostKeyLine()));

		// An empty set is not "clear the anchors": a node with none does not fall back
		// to trust-on-first-use, it stops working.
		putAnchors(token, id, Map.of()).expectStatus().isEqualTo(422);
		putAnchors(token, id, Map.of("pinnedHostKey", "not-an-openssh-line")).expectStatus().isEqualTo(422);
		putAnchors(token, id, Map.of("hostCertificate", "ssh-ed25519-cert-v01@openssh.com !!!not-base64!!!"))
				.expectStatus().isEqualTo(422);

		// A refused replace changed nothing.
		assertThat(anchors(token, id)).hasSize(1);
	}

	@Test
	void anUnknownNodeIs404AndARemovedNodeIs409() {
		String token = tokenWith("svc-anchor-state-" + unique(), PlatformPermissions.NODE_ENROLL,
				PlatformPermissions.NODE_REMOVE);
		Map<String, Object> anchor = Map.of("pinnedHostKey", pinnedHostKeyLine());

		putAnchors(token, UUID.randomUUID(), anchor).expectStatus().isNotFound();
		client.get().uri("/v1/nodes/" + UUID.randomUUID() + "/host-anchors").header("Authorization", "Bearer " + token)
				.exchange().expectStatus().isNotFound();

		UUID id = registerAgentless(token, Map.of("pinnedHostKey", pinnedHostKeyLine()));
		client.delete().uri("/v1/nodes/" + id).header("Authorization", "Bearer " + token).exchange().expectStatus()
				.isNoContent();
		// Removal is terminal: a removed node is replaced by a fresh registration, not
		// repaired.
		putAnchors(token, id, anchor).expectStatus().isEqualTo(409);
	}

	@Test
	void bothRoutesAreGatedOnNodeEnroll() {
		String token = tokenWith("svc-anchor-rbac-" + unique(), PlatformPermissions.NODE_ENROLL);
		UUID id = registerAgentless(token, Map.of("pinnedHostKey", pinnedHostKeyLine()));
		String none = tokenWith("svc-anchor-none-" + unique());

		client.get().uri("/v1/nodes/" + id + "/host-anchors").header("Authorization", "Bearer " + none).exchange()
				.expectStatus().isForbidden();
		putAnchors(none, id, Map.of("pinnedHostKey", pinnedHostKeyLine())).expectStatus().isForbidden();
	}

	@Test
	void theIdempotencyKeyReplaysRatherThanReplacingTwice() {
		String admin = "svc-anchor-idem-" + unique();
		String token = tokenWith(admin, PlatformPermissions.NODE_ENROLL);
		UUID id = registerAgentless(token, Map.of("pinnedHostKey", pinnedHostKeyLine()));
		String key = "idem-" + unique();
		Map<String, Object> body = Map.of("pinnedHostKey", pinnedHostKeyLine());

		Map<?, ?> first = putAnchors(token, id, body, key).expectStatus().isOk().expectBody(Map.class).returnResult()
				.getResponseBody();
		Map<?, ?> replay = putAnchors(token, id, body, key).expectStatus().isOk().expectBody(Map.class).returnResult()
				.getResponseBody();
		assertThat(replay).isEqualTo(first);

		// The replay returned the stored response instead of re-running the replace —
		// which is what the single audit record proves.
		assertThat(replays(admin)).isEqualTo(1);

		// The same key with a different body is the reuse the guard exists to catch.
		putAnchors(token, id, Map.of("pinnedHostKey", pinnedHostKeyLine()), key).expectStatus().isEqualTo(422);
	}

	private long replays(String actor) {
		return auditEvents.findByActor(actor).collectList().block().stream().map(AuditEvent::action)
				.filter("node.host_anchors.replace"::equals).count();
	}

	private String health(String token, UUID id) {
		Map<?, ?> node = client.get().uri("/v1/nodes/" + id).header("Authorization", "Bearer " + token).exchange()
				.expectStatus().isOk().expectBody(Map.class).returnResult().getResponseBody();
		return (String) node.get("health");
	}

	@SuppressWarnings("unchecked")
	private List<Map<String, Object>> anchors(String token, UUID id) {
		Map<?, ?> body = client.get().uri("/v1/nodes/" + id + "/host-anchors")
				.header("Authorization", "Bearer " + token).exchange().expectStatus().isOk().expectBody(Map.class)
				.returnResult().getResponseBody();
		return (List<Map<String, Object>>) body.get("anchors");
	}

	private WebTestClient.ResponseSpec putAnchors(String token, UUID id, Map<String, Object> body) {
		return putAnchors(token, id, body, null);
	}

	private WebTestClient.ResponseSpec putAnchors(String token, UUID id, Map<String, Object> body,
			String idempotencyKey) {
		WebTestClient.RequestBodySpec request = client.put().uri("/v1/nodes/" + id + "/host-anchors")
				.header("Authorization", "Bearer " + token).contentType(MediaType.APPLICATION_JSON);
		if (idempotencyKey != null) {
			request = request.header("Idempotency-Key", idempotencyKey);
		}
		return request.bodyValue(body).exchange();
	}

	private UUID registerAgentless(String token, Map<String, Object> anchors) {
		Map<String, Object> body = new java.util.LinkedHashMap<>(anchors);
		body.put("name", "host-" + unique());
		body.put("address", "10.0.0.5:22");
		return register(token, body);
	}

	private UUID register(String token, Map<String, Object> body) {
		Map<?, ?> created = client.post().uri("/v1/nodes").header("Authorization", "Bearer " + token)
				.contentType(MediaType.APPLICATION_JSON).bodyValue(body).exchange().expectStatus().isCreated()
				.expectBody(Map.class).returnResult().getResponseBody();
		return UUID.fromString(created.get("id").toString());
	}

	// A certificate line, not a key line: the first token is the CERTIFICATE type,
	// which is what the key_type CHECK used to reject. The CP never parses the blob
	// (it hands the wire bytes to the Gateway), so random material is faithful
	// here.
	private static String hostCertificateLine() {
		return "ssh-ed25519-cert-v01@openssh.com " + randomBlob(120) + " host@" + unique();
	}

	private static String pinnedHostKeyLine() {
		return "ecdsa-sha2-nistp256 " + randomBlob(48) + " host@" + unique();
	}

	private static String randomBlob(int bytes) {
		byte[] blob = new byte[bytes];
		RANDOM.nextBytes(blob);
		return Base64.getEncoder().encodeToString(blob);
	}

	private static String fingerprintOf(String openSshLine) throws java.security.NoSuchAlgorithmException {
		byte[] blob = Base64.getDecoder().decode(openSshLine.trim().split("\\s+")[1]);
		byte[] digest = java.security.MessageDigest.getInstance("SHA-256").digest(blob);
		return "SHA256:" + Base64.getEncoder().withoutPadding().encodeToString(digest);
	}

	private String tokenWith(String saName, String... permissions) {
		ServiceAccount sa = serviceAccounts
				.save(ServiceAccount.create(saName, "test", "client_secret", null, null, "api")).block();
		var issued = machineIdentity.issueCredential(sa.id(), "client_secret", null, null, null, null, "admin").block();
		if (permissions.length > 0) {
			PlatformRole role = roles.save(
					PlatformRole.create("anchor-role-" + UUID.randomUUID(), List.of(permissions), "test", "default"))
					.block();
			bindings.save(RoleBinding.create(role.id(), "user", saName, null, "default")).block();
		}
		var token = machineIdentity.issueToken(new MachineIdentityService.TokenRequest("client_credentials", saName,
				null, null, issued.clientSecret(), null), null, "203.0.113.30").block();
		return token.accessToken();
	}

	private static String unique() {
		return UUID.randomUUID().toString().substring(0, 8);
	}
}
