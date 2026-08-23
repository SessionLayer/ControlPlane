package io.sessionlayer.controlplane.web;

import static org.assertj.core.api.Assertions.assertThat;

import io.sessionlayer.controlplane.data.Uuids;
import io.sessionlayer.controlplane.data.runtime.AuditEvent;
import io.sessionlayer.controlplane.data.runtime.GatewayIdentity;
import io.sessionlayer.controlplane.data.runtime.GatewayIdentityRepository;
import io.sessionlayer.controlplane.data.runtime.Node;
import io.sessionlayer.controlplane.data.runtime.NodeRepository;
import io.sessionlayer.controlplane.data.runtime.Presence;
import io.sessionlayer.controlplane.data.runtime.PresenceRepository;
import io.sessionlayer.controlplane.data.runtime.RecordingRef;
import io.sessionlayer.controlplane.data.runtime.RecordingRefRepository;
import io.sessionlayer.controlplane.data.runtime.SshSession;
import io.sessionlayer.controlplane.data.runtime.SshSessionRepository;
import io.sessionlayer.controlplane.platform.PlatformPermissions;
import io.sessionlayer.controlplane.support.AbstractConfigApiIT;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

class GatewayDirectoryIT extends AbstractConfigApiIT {

	@Autowired
	private GatewayIdentityRepository gatewayIdentities;
	@Autowired
	private PresenceRepository presence;
	@Autowired
	private NodeRepository nodes;
	@Autowired
	private SshSessionRepository sshSessions;
	@Autowired
	private RecordingRefRepository recordings;
	@Autowired
	private ObjectMapper objectMapper;

	private static final String[] PROJECTION = {"id", "name", "fingerprintSha256", "prevFingerprintSha256",
			"generation", "joinMethod", "status", "issuedAt", "notAfter", "presenceNodeCount", "presenceLastSeenAt",
			"createdAt", "updatedAt"};

	private final List<UUID> seededGateways = new ArrayList<>();
	private final List<UUID> seededNodes = new ArrayList<>();
	private final List<UUID> seededSessions = new ArrayList<>();
	private final List<UUID> seededRecordings = new ArrayList<>();

	@AfterEach
	void cleanUp() {
		seededRecordings.forEach(id -> recordings.deleteById(id).block());
		seededSessions.forEach(id -> sshSessions.deleteById(id).block());
		seededNodes.forEach(id -> nodes.deleteById(id).block());
		seededGateways.forEach(id -> gatewayIdentities.deleteById(id).block());
		seededRecordings.clear();
		seededSessions.clear();
		seededNodes.clear();
		seededGateways.clear();
	}

	@Test
	void listRequiresGatewayEnrollAndRefusesEveryOtherBinding() {
		String none = tokenWith("svc-gw-none-" + UUID.randomUUID());
		client.get().uri("/v1/gateways").header("Authorization", "Bearer " + none).exchange().expectStatus()
				.isForbidden();

		String configReader = tokenWith("svc-gw-rbacread-" + UUID.randomUUID(), PlatformPermissions.RBAC_READ);
		client.get().uri("/v1/gateways").header("Authorization", "Bearer " + configReader).exchange().expectStatus()
				.isForbidden();

		String reader = tokenWith("svc-gw-read-" + UUID.randomUUID(), PlatformPermissions.GATEWAY_ENROLL);
		client.get().uri("/v1/gateways").header("Authorization", "Bearer " + reader).exchange().expectStatus().isOk();
	}

	/**
	 * The projection is the disclosure boundary, so assert on the whole response
	 * body: the identity's key-material reference must not appear under any name,
	 * and no field outside the metadata set may be present.
	 */
	@Test
	void theListingIsMetadataOnlyAndNeverCarriesTheIdentityReference() {
		String name = "gw-meta-" + suffix();
		String identityRef = "mtls:" + UUID.randomUUID();
		GatewayIdentity gateway = seedGateway(name, identityRef, "active", Instant.now().plusSeconds(3600));

		String reader = tokenWith("svc-gw-meta-" + UUID.randomUUID(), PlatformPermissions.GATEWAY_ENROLL);
		byte[] raw = client.get().uri("/v1/gateways?name=" + name).header("Authorization", "Bearer " + reader)
				.exchange().expectStatus().isOk().expectBody().returnResult().getResponseBody();
		String body = new String(raw, java.nio.charset.StandardCharsets.UTF_8);
		assertThat(body).doesNotContain(identityRef).doesNotContain("mtlsIdentityRef");

		JsonNode item = objectMapper.readTree(raw).get("items").get(0);
		assertThat(fieldNames(item)).isSubsetOf(PROJECTION);
		assertThat(item.get("id").asString()).isEqualTo(gateway.id().toString());
		assertThat(item.get("fingerprintSha256").asString()).isEqualTo("fp-" + name);
		assertThat(item.get("presenceNodeCount").asInt()).isZero();
	}

	/**
	 * A generation-0 identity has no previous digest, and the field must be ABSENT
	 * rather than empty - an empty string reads as a real digest matching nothing,
	 * which is the ambiguity the field exists to remove, inverted.
	 */
	@Test
	void theSupersededFingerprintIsAbsentBeforeTheFirstRenewalAndPresentAfter() {
		String fresh = "gw-gen0-" + suffix();
		GatewayIdentity enrolled = seedGateway(fresh, "mtls:" + UUID.randomUUID(), "active", null);
		String renewed = "gw-gen1-" + suffix();
		GatewayIdentity rotated = gatewayIdentities
				.save(new GatewayIdentity(Uuids.v7(), renewed, "mtls:" + UUID.randomUUID(), "fp-current", "fp-previous",
						1L, "token", "active", Instant.now(), null, null, null, null, null, null, null))
				.block();
		seededGateways.add(rotated.id());

		String reader = tokenWith("svc-gw-prevfp-" + UUID.randomUUID(), PlatformPermissions.GATEWAY_ENROLL);
		JsonNode gen0 = one(reader, enrolled.id());
		assertThat(gen0.hasNonNull("prevFingerprintSha256")).isFalse();
		assertThat(new String(rawOne(reader, enrolled.id()), java.nio.charset.StandardCharsets.UTF_8))
				.doesNotContain("prevFingerprintSha256");

		JsonNode gen1 = one(reader, rotated.id());
		assertThat(gen1.get("fingerprintSha256").asString()).isEqualTo("fp-current");
		assertThat(gen1.get("prevFingerprintSha256").asString()).isEqualTo("fp-previous");
	}

	@Test
	void listFiltersByNameAndStatus() {
		String tag = suffix();
		GatewayIdentity active = seedGateway("gw-f-active-" + tag, "mtls:a-" + tag, "active", null);
		GatewayIdentity locked = seedGateway("gw-f-locked-" + tag, "mtls:l-" + tag, "locked", null);

		String reader = tokenWith("svc-gw-filter-" + UUID.randomUUID(), PlatformPermissions.GATEWAY_ENROLL);
		assertThat(idsOf(reader, "?name=" + active.name())).containsExactly(active.id());
		assertThat(idsOf(reader, "?status=locked")).contains(locked.id()).doesNotContain(active.id());
	}

	@Test
	void getReturnsTheSameProjectionAndIsGatedTheSameWay() {
		String name = "gw-get-" + suffix();
		GatewayIdentity gateway = seedGateway(name, "mtls:" + UUID.randomUUID(), "active", null);

		String configReader = tokenWith("svc-gw-getrbac-" + UUID.randomUUID(), PlatformPermissions.RBAC_READ);
		client.get().uri("/v1/gateways/" + gateway.id()).header("Authorization", "Bearer " + configReader).exchange()
				.expectStatus().isForbidden();

		String reader = tokenWith("svc-gw-get-" + UUID.randomUUID(), PlatformPermissions.GATEWAY_ENROLL);
		byte[] raw = client.get().uri("/v1/gateways/" + gateway.id()).header("Authorization", "Bearer " + reader)
				.exchange().expectStatus().isOk().expectBody().returnResult().getResponseBody();
		JsonNode resource = objectMapper.readTree(raw);
		assertThat(resource.get("name").asString()).isEqualTo(name);
		assertThat(fieldNames(resource)).isSubsetOf(PROJECTION);

		client.get().uri("/v1/gateways/" + UUID.randomUUID()).header("Authorization", "Bearer " + reader).exchange()
				.expectStatus().isNotFound();
	}

	@Test
	void removeIsGatedByGatewayRemoveAndNotByGatewayEnroll() {
		GatewayIdentity gateway = seedGateway("gw-perm-" + suffix(), "mtls:" + UUID.randomUUID(), "active", null);

		String enroller = tokenWith("svc-gw-enroller-" + UUID.randomUUID(), PlatformPermissions.GATEWAY_ENROLL);
		client.delete().uri("/v1/gateways/" + gateway.id()).header("Authorization", "Bearer " + enroller).exchange()
				.expectStatus().isForbidden();
		assertThat(gatewayIdentities.findById(gateway.id()).blockOptional()).isPresent();

		String remover = tokenWith("svc-gw-remover-" + UUID.randomUUID(), PlatformPermissions.GATEWAY_REMOVE);
		client.delete().uri("/v1/gateways/" + gateway.id()).header("Authorization", "Bearer " + remover).exchange()
				.expectStatus().isNoContent();
		assertThat(gatewayIdentities.findById(gateway.id()).blockOptional()).isEmpty();
		assertThat(gatewayIdentities.findByName(gateway.name()).blockOptional()).isEmpty();
	}

	@Test
	void removingAnUnknownGatewayIsNotFound() {
		String remover = tokenWith("svc-gw-absent-" + UUID.randomUUID(), PlatformPermissions.GATEWAY_REMOVE);
		client.delete().uri("/v1/gateways/" + UUID.randomUUID()).header("Authorization", "Bearer " + remover).exchange()
				.expectStatus().isNotFound();
	}

	@Test
	void removalIsRefusedWhilePresenceIsHeldAndForcedRemovalIsADistinctAuditAction() {
		String name = "gw-presence-" + suffix();
		GatewayIdentity gateway = seedGateway(name, "mtls:" + UUID.randomUUID(), "active", null);
		seedPresence(name, Instant.now());

		String remover = tokenWith("svc-gw-force-" + UUID.randomUUID(), PlatformPermissions.GATEWAY_REMOVE);
		client.delete().uri("/v1/gateways/" + gateway.id()).header("Authorization", "Bearer " + remover).exchange()
				.expectStatus().isEqualTo(409);
		assertThat(gatewayIdentities.findById(gateway.id()).blockOptional()).isPresent();
		assertThat(actionsFor(name)).isEmpty();

		client.delete().uri("/v1/gateways/" + gateway.id() + "?force=true").header("Authorization", "Bearer " + remover)
				.exchange().expectStatus().isNoContent();
		assertThat(gatewayIdentities.findById(gateway.id()).blockOptional()).isEmpty();
		assertThat(actionsFor(name)).containsExactly("gateway.remove_forced");

		AuditEvent event = eventsFor(name).get(0);
		assertThat(event.detail().get("presence_node_count").asString()).isEqualTo("1");
		assertThat(event.detail().get("force_requested").asString()).isEqualTo("true");
	}

	@Test
	void anUncontestedRemovalUsesTheOrdinaryAuditAction() {
		String name = "gw-plain-" + suffix();
		GatewayIdentity gateway = seedGateway(name, "mtls:" + UUID.randomUUID(), "active", null);

		String remover = tokenWith("svc-gw-plain-" + UUID.randomUUID(), PlatformPermissions.GATEWAY_REMOVE);
		client.delete().uri("/v1/gateways/" + gateway.id() + "?force=true").header("Authorization", "Bearer " + remover)
				.exchange().expectStatus().isNoContent();

		// force was requested but nothing was overridden, so this is the ordinary
		// action: the forced name must mean "a live owner was taken down".
		assertThat(actionsFor(name)).containsExactly("gateway.remove");
	}

	/**
	 * A Gateway past the HA staleness window owns nothing a peer would not already
	 * take over, so it must not need force. Presence release ages last_seen to the
	 * epoch, which is the same state.
	 */
	@Test
	void stalePresenceDoesNotBlockRemoval() {
		String name = "gw-stale-" + suffix();
		GatewayIdentity gateway = seedGateway(name, "mtls:" + UUID.randomUUID(), "active", null);
		seedPresence(name, Instant.EPOCH);

		String remover = tokenWith("svc-gw-stale-" + UUID.randomUUID(), PlatformPermissions.GATEWAY_REMOVE);
		client.delete().uri("/v1/gateways/" + gateway.id()).header("Authorization", "Bearer " + remover).exchange()
				.expectStatus().isNoContent();
		assertThat(actionsFor(name)).containsExactly("gateway.remove");
	}

	/**
	 * The removal guard must look at open sessions, not only at presence. A Gateway
	 * whose heartbeat has merely lapsed is still bridging traffic, and the FK's ON
	 * DELETE SET NULL is what {@code RecordingRegistrationService} authorises
	 * upload and finalize on - so a presence-only guard would let an ordinary
	 * removal strand every in-flight recording at status 'recording' for ever.
	 */
	@Test
	void removalIsRefusedWhileSessionsAreOpenEvenWithNoFreshPresence() {
		String name = "gw-openses-" + suffix();
		GatewayIdentity gateway = seedGateway(name, "mtls:" + UUID.randomUUID(), "active", null);
		SshSession session = seedOpenSession(gateway.id(), name);
		RecordingRef recording = seedRecording(session.id());

		String remover = tokenWith("svc-gw-openses-" + UUID.randomUUID(), PlatformPermissions.GATEWAY_REMOVE);
		client.delete().uri("/v1/gateways/" + gateway.id()).header("Authorization", "Bearer " + remover).exchange()
				.expectStatus().isEqualTo(409);

		assertThat(gatewayIdentities.findById(gateway.id()).blockOptional()).isPresent();
		assertThat(sshSessions.findById(session.id()).block().endedAt()).isNull();
		assertThat(recordings.findById(recording.id()).block().status()).isEqualTo("recording");
		assertThat(actionsFor(name)).isEmpty();
	}

	@Test
	void aForcedRemovalEndsStrandedSessionsAndFailsTheirRecordings() {
		String name = "gw-strand-" + suffix();
		GatewayIdentity gateway = seedGateway(name, "mtls:" + UUID.randomUUID(), "active", null);
		SshSession session = seedOpenSession(gateway.id(), name);
		RecordingRef recording = seedRecording(session.id());

		String remover = tokenWith("svc-gw-strand-" + UUID.randomUUID(), PlatformPermissions.GATEWAY_REMOVE);
		client.delete().uri("/v1/gateways/" + gateway.id() + "?force=true").header("Authorization", "Bearer " + remover)
				.exchange().expectStatus().isNoContent();

		SshSession ended = sshSessions.findById(session.id()).block();
		assertThat(ended.endedAt()).isNotNull();
		assertThat(ended.endReason()).isEqualTo("gateway_removed");
		assertThat(recordings.findById(recording.id()).block().status()).isEqualTo("failed");

		assertThat(actionsFor(name)).containsExactly("gateway.remove_forced");
		AuditEvent event = eventsFor(name).get(0);
		assertThat(event.detail().get("open_session_count").asString()).isEqualTo("1");
		assertThat(event.detail().get("presence_node_count").asString()).isEqualTo("0");
	}

	@Test
	void anEndedSessionDoesNotBlockRemoval() {
		String name = "gw-closed-" + suffix();
		GatewayIdentity gateway = seedGateway(name, "mtls:" + UUID.randomUUID(), "active", null);
		SshSession session = seedOpenSession(gateway.id(), name);
		sshSessions.save(session.ended(Instant.now(), "client")).block();

		String remover = tokenWith("svc-gw-closed-" + UUID.randomUUID(), PlatformPermissions.GATEWAY_REMOVE);
		client.delete().uri("/v1/gateways/" + gateway.id()).header("Authorization", "Bearer " + remover).exchange()
				.expectStatus().isNoContent();
		assertThat(actionsFor(name)).containsExactly("gateway.remove");
	}

	private static String suffix() {
		return UUID.randomUUID().toString().substring(0, 8);
	}

	private GatewayIdentity seedGateway(String name, String identityRef, String status, Instant notAfter) {
		GatewayIdentity gateway = new GatewayIdentity(Uuids.v7(), name, identityRef, "fp-" + name, null, 0L, "token",
				status, Instant.now(), notAfter, null, null, null, null, null, null);
		GatewayIdentity saved = gatewayIdentities.save(gateway).block();
		seededGateways.add(saved.id());
		return saved;
	}

	private void seedPresence(String owningGateway, Instant lastSeen) {
		Node node = nodes.save(
				Node.create("node-" + suffix(), null, objectMapper.createObjectNode(), "agent", "active", "10.0.0.5"))
				.block();
		seededNodes.add(node.id());
		presence.save(Presence.create(node.id(), owningGateway, "10.0.0.5:9443", 1L, UUID.randomUUID(), lastSeen))
				.block();
	}

	private SshSession seedOpenSession(UUID gatewayId, String gatewayName) {
		SshSession session = sshSessions
				.save(SshSession.create("alice-" + suffix(), null, null, "root", gatewayId, gatewayName, "standing",
						List.of("shell"), null, null, null, null, 0L, Instant.now().plusSeconds(3600), Instant.now()))
				.block();
		seededSessions.add(session.id());
		return session;
	}

	private RecordingRef seedRecording(UUID sessionId) {
		RecordingRef recording = recordings
				.save(RecordingRef.create(sessionId, "spool/" + sessionId, "ref", "head", "governance", 0L)).block();
		seededRecordings.add(recording.id());
		return recording;
	}

	private byte[] rawOne(String token, UUID gatewayId) {
		return client.get().uri("/v1/gateways/" + gatewayId).header("Authorization", "Bearer " + token).exchange()
				.expectStatus().isOk().expectBody().returnResult().getResponseBody();
	}

	private JsonNode one(String token, UUID gatewayId) {
		return objectMapper.readTree(rawOne(token, gatewayId));
	}

	private List<UUID> idsOf(String token, String query) {
		byte[] raw = client.get().uri("/v1/gateways" + query).header("Authorization", "Bearer " + token).exchange()
				.expectStatus().isOk().expectBody().returnResult().getResponseBody();
		List<UUID> ids = new ArrayList<>();
		objectMapper.readTree(raw).get("items").forEach(item -> ids.add(UUID.fromString(item.get("id").asString())));
		return ids;
	}

	private List<AuditEvent> eventsFor(String gatewayName) {
		return auditEvents.findAll().filter(event -> gatewayName.equals(event.subject()))
				.filter(event -> event.action().startsWith("gateway.remove")).collectList().block();
	}

	private List<String> actionsFor(String gatewayName) {
		return eventsFor(gatewayName).stream().map(AuditEvent::action).toList();
	}

	private static List<String> fieldNames(JsonNode node) {
		List<String> names = new ArrayList<>();
		node.properties().forEach(property -> names.add(property.getKey()));
		return names;
	}
}
