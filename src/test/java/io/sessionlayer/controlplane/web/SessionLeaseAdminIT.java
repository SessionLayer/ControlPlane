package io.sessionlayer.controlplane.web;

import static org.assertj.core.api.Assertions.assertThat;

import io.sessionlayer.controlplane.data.Uuids;
import io.sessionlayer.controlplane.data.runtime.AuditEvent;
import io.sessionlayer.controlplane.data.runtime.SessionLease;
import io.sessionlayer.controlplane.data.runtime.SessionLeaseRepository;
import io.sessionlayer.controlplane.data.runtime.SshSession;
import io.sessionlayer.controlplane.data.runtime.SshSessionRepository;
import io.sessionlayer.controlplane.platform.PlatformPermissions;
import io.sessionlayer.controlplane.support.AbstractConfigApiIT;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.test.web.reactive.server.WebTestClient;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

class SessionLeaseAdminIT extends AbstractConfigApiIT {

	@Autowired
	private SessionLeaseRepository leases;
	@Autowired
	private SshSessionRepository sshSessions;
	@Autowired
	private ObjectMapper objectMapper;

	private final List<UUID> seeded = new ArrayList<>();
	private final List<UUID> seededSessions = new ArrayList<>();

	@AfterEach
	void cleanUp() {
		// Leases first: session_lease.session_id references ssh_session.
		seeded.forEach(id -> leases.deleteById(id).block());
		seededSessions.forEach(id -> sshSessions.deleteById(id).block());
		seeded.clear();
		seededSessions.clear();
	}

	@Test
	void readIsGatedByAuditReadAndReleaseByLockWrite() {
		SessionLease lease = seed("lease-rbac-" + suffix(), Instant.now().plus(Duration.ofHours(1)), null);

		String none = tokenWith("svc-lease-none-" + UUID.randomUUID());
		client.get().uri("/v1/session-leases").header("Authorization", "Bearer " + none).exchange().expectStatus()
				.isForbidden();
		String lockReader = tokenWith("svc-lease-lockread-" + UUID.randomUUID(), PlatformPermissions.LOCK_READ);
		client.get().uri("/v1/session-leases").header("Authorization", "Bearer " + lockReader).exchange().expectStatus()
				.isForbidden();
		String auditor = tokenWith("svc-lease-auditor-" + UUID.randomUUID(), PlatformPermissions.AUDIT_READ);
		client.get().uri("/v1/session-leases").header("Authorization", "Bearer " + auditor).exchange().expectStatus()
				.isOk();

		release(auditor, lease.id(), "auditor should not be able to do this").expectStatus().isForbidden();
		String writer = tokenWith("svc-lease-writer-" + UUID.randomUUID(), PlatformPermissions.LOCK_WRITE);
		release(writer, lease.id(), "operator confirmed the session is gone").expectStatus().isOk();
	}

	@Test
	void countsTowardCapMatchesTheEnforcementPredicate() {
		String identity = "lease-count-" + suffix();
		SessionLease live = seed(identity, Instant.now().plus(Duration.ofHours(1)), null);
		SessionLease expired = seed(identity, Instant.now().minus(Duration.ofHours(1)), null);
		SessionLease released = seed(identity, Instant.now().plus(Duration.ofHours(1)), Instant.now());

		assertThat(leases.countLiveByIdentity(identity, Instant.now()).block()).isEqualTo(1L);

		String auditor = tokenWith("svc-lease-count-" + UUID.randomUUID(), PlatformPermissions.AUDIT_READ);
		assertThat(counting(auditor, "?identity=" + identity, live.id())).isTrue();
		assertThat(counting(auditor, "?identity=" + identity, expired.id())).isFalse();
		assertThat(counting(auditor, "?identity=" + identity, released.id())).isFalse();

		assertThat(ids(auditor, "?identity=" + identity + "&activeOnly=true")).containsExactly(live.id());
		assertThat(ids(auditor, "?identity=" + identity + "&activeOnly=false")).containsExactlyInAnyOrder(expired.id(),
				released.id());
		assertThat(ids(auditor, "?identity=" + identity)).containsExactlyInAnyOrder(live.id(), expired.id(),
				released.id());
	}

	@Test
	void getReturnsOneLeaseUnderTheReadPermission() {
		String identity = "lease-get-" + suffix();
		SessionLease lease = seed(identity, Instant.now().plus(Duration.ofHours(1)), null);

		String writer = tokenWith("svc-lease-getwrite-" + UUID.randomUUID(), PlatformPermissions.LOCK_WRITE);
		client.get().uri("/v1/session-leases/" + lease.id()).header("Authorization", "Bearer " + writer).exchange()
				.expectStatus().isForbidden();

		String auditor = tokenWith("svc-lease-get-" + UUID.randomUUID(), PlatformPermissions.AUDIT_READ);
		byte[] raw = client.get().uri("/v1/session-leases/" + lease.id()).header("Authorization", "Bearer " + auditor)
				.exchange().expectStatus().isOk().expectBody().returnResult().getResponseBody();
		JsonNode resource = objectMapper.readTree(raw);
		assertThat(resource.get("identity").asString()).isEqualTo(identity);
		assertThat(resource.get("countsTowardCap").asBoolean()).isTrue();

		client.get().uri("/v1/session-leases/" + UUID.randomUUID()).header("Authorization", "Bearer " + auditor)
				.exchange().expectStatus().isNotFound();
	}

	@Test
	void releasingOneLeaseFreesExactlyOneSlotAndIsAudited() {
		String identity = "lease-free-" + suffix();
		SessionLease first = seed(identity, Instant.now().plus(Duration.ofHours(1)), null);
		seed(identity, Instant.now().plus(Duration.ofHours(1)), null);
		seed(identity, Instant.now().plus(Duration.ofHours(1)), null);
		String other = "lease-bystander-" + suffix();
		seed(other, Instant.now().plus(Duration.ofHours(1)), null);
		assertThat(leases.countLiveByIdentity(identity, Instant.now()).block()).isEqualTo(3L);

		String writer = tokenWith("svc-lease-free-" + UUID.randomUUID(), PlatformPermissions.LOCK_WRITE);
		release(writer, first.id(), "restore left a ghost lease").expectStatus().isOk();

		assertThat(leases.countLiveByIdentity(identity, Instant.now()).block()).isEqualTo(2L);
		assertThat(leases.countLiveByIdentity(other, Instant.now()).block()).isEqualTo(1L);
		assertThat(leases.findById(first.id()).block().releasedAt()).isNotNull();

		AuditEvent event = releaseEventsFor(identity).get(0);
		assertThat(event.detail().get("reason").asString()).isEqualTo("restore left a ghost lease");
		assertThat(event.detail().get("released_by_this_call").asString()).isEqualTo("true");
		assertThat(event.subject()).isEqualTo(identity);
	}

	@Test
	void repeatingAReleaseDoesNotDecrementTwice() {
		String identity = "lease-idem-" + suffix();
		SessionLease lease = seed(identity, Instant.now().plus(Duration.ofHours(1)), null);
		seed(identity, Instant.now().plus(Duration.ofHours(1)), null);

		String writer = tokenWith("svc-lease-idem-" + UUID.randomUUID(), PlatformPermissions.LOCK_WRITE);
		release(writer, lease.id(), "first release").expectStatus().isOk();
		Instant firstReleasedAt = leases.findById(lease.id()).block().releasedAt();

		release(writer, lease.id(), "second release").expectStatus().isOk();
		assertThat(leases.findById(lease.id()).block().releasedAt()).isEqualTo(firstReleasedAt);
		assertThat(leases.countLiveByIdentity(identity, Instant.now()).block()).isEqualTo(1L);

		List<AuditEvent> events = releaseEventsFor(identity);
		assertThat(events).hasSize(2);
		assertThat(events.stream().map(e -> e.detail().get("released_by_this_call").asString()).toList())
				.containsExactlyInAnyOrder("true", "false");
	}

	@Test
	void aReleaseAndTheReaperCannotBothStampTheSameLease() {
		String identity = "lease-reap-" + suffix();
		String writer = tokenWith("svc-lease-reap-" + UUID.randomUUID(), PlatformPermissions.LOCK_WRITE);
		Instant past = Instant.now().minus(Duration.ofHours(2));

		SessionLease releasedFirst = seed(identity, past, null);
		release(writer, releasedFirst.id(), "operator got there first").expectStatus().isOk();
		Instant operatorStamp = leases.findById(releasedFirst.id()).block().releasedAt();
		leases.reapExpired(Instant.now(), Instant.now()).block();
		assertThat(leases.findById(releasedFirst.id()).block().releasedAt()).isEqualTo(operatorStamp);

		SessionLease reapedFirst = seed(identity, past, null);
		leases.reapExpired(Instant.now(), Instant.now()).block();
		Instant reaperStamp = leases.findById(reapedFirst.id()).block().releasedAt();
		assertThat(reaperStamp).isNotNull();
		release(writer, reapedFirst.id(), "operator arrived after the reaper").expectStatus().isOk();
		assertThat(leases.findById(reapedFirst.id()).block().releasedAt()).isEqualTo(reaperStamp);

		assertThat(leases.countLiveByIdentity(identity, Instant.now()).block()).isZero();
	}

	@Test
	void anExtendCannotUndoARelease() {
		String identity = "lease-extend-" + suffix();
		SessionLease lease = seedForSession(identity, Instant.now().plus(Duration.ofMinutes(5)));
		UUID sessionId = lease.sessionId();

		assertThat(leases.extendBySessionId(sessionId, Instant.now().plus(Duration.ofHours(1))).block()).isEqualTo(1);

		String writer = tokenWith("svc-lease-extend-" + UUID.randomUUID(), PlatformPermissions.LOCK_WRITE);
		release(writer, lease.id(), "session confirmed dead").expectStatus().isOk();

		assertThat(leases.extendBySessionId(sessionId, Instant.now().plus(Duration.ofHours(2))).block()).isZero();
		assertThat(leases.findById(lease.id()).block().releasedAt()).isNotNull();
		assertThat(leases.countLiveByIdentity(identity, Instant.now()).block()).isZero();
	}

	@Test
	void aReasonIsRequiredAndAnUnknownLeaseIsNotFound() {
		SessionLease lease = seed("lease-reason-" + suffix(), Instant.now().plus(Duration.ofHours(1)), null);
		String writer = tokenWith("svc-lease-reason-" + UUID.randomUUID(), PlatformPermissions.LOCK_WRITE);

		// A bodiless reason is rejected before the release either by bean validation on
		// the required field or by the service; what must hold is that nothing is
		// released, so assert the effect rather than which of the two answered.
		client.post().uri("/v1/session-leases/" + lease.id() + "/release").header("Authorization", "Bearer " + writer)
				.contentType(MediaType.APPLICATION_JSON).bodyValue("{}").exchange().expectStatus().is4xxClientError();
		release(writer, lease.id(), "   ").expectStatus().isEqualTo(422);
		assertThat(leases.findById(lease.id()).block().releasedAt()).isNull();

		release(writer, UUID.randomUUID(), "no such lease").expectStatus().isNotFound();
	}

	@Test
	void thereIsNoBulkReleaseAndAnIdentityParameterIsInert() {
		String identity = "lease-nobulk-" + suffix();
		SessionLease target = seed(identity, Instant.now().plus(Duration.ofHours(1)), null);
		seed(identity, Instant.now().plus(Duration.ofHours(1)), null);
		seed(identity, Instant.now().plus(Duration.ofHours(1)), null);

		String writer = tokenWith("svc-lease-nobulk-" + UUID.randomUUID(), PlatformPermissions.LOCK_WRITE);
		// The router answers 405, not 404, because the path matches the single-lease
		// GET template with the id reading as "release". That is the correct answer and
		// discloses nothing a reader of the contract does not already have: it says
		// /v1/session-leases/{id} exists, which is published, and NOT that a
		// collection-level release exists. The invariant under test is that no bulk
		// form succeeds and nothing is released by attempting one, so assert that
		// rather than a status code whose value is an artefact of route matching.
		client.post().uri("/v1/session-leases/release").header("Authorization", "Bearer " + writer)
				.contentType(MediaType.APPLICATION_JSON).bodyValue("{\"reason\":\"bulk\"}").exchange().expectStatus()
				.is4xxClientError();
		assertThat(leases.countLiveByIdentity(identity, Instant.now()).block()).isEqualTo(3L);

		client.post().uri("/v1/session-leases/" + target.id() + "/release?identity=" + identity)
				.header("Authorization", "Bearer " + writer).contentType(MediaType.APPLICATION_JSON)
				.bodyValue("{\"reason\":\"one lease only\"}").exchange().expectStatus().isOk();
		assertThat(leases.countLiveByIdentity(identity, Instant.now()).block()).isEqualTo(2L);
	}

	private static String suffix() {
		return UUID.randomUUID().toString().substring(0, 8);
	}

	private SessionLease seed(String identity, Instant expiresAt, Instant releasedAt) {
		return persist(new SessionLease(Uuids.v7(), identity, null, "gw-test", Instant.now(), expiresAt, releasedAt,
				null, null, null));
	}

	// session_lease.session_id is a real FK, so the extend path needs a session row
	// to point at rather than a bare id.
	private SessionLease seedForSession(String identity, Instant expiresAt) {
		SshSession session = sshSessions.save(SshSession.create(identity, null, null, "root", null, "gw-test",
				"standing", List.of("shell"), null, null, null, null, 0L, expiresAt, Instant.now())).block();
		seededSessions.add(session.id());
		return persist(SessionLease.acquire(identity, session.id(), "gw-test", Instant.now(), expiresAt));
	}

	private SessionLease persist(SessionLease lease) {
		SessionLease saved = leases.save(lease).block();
		seeded.add(saved.id());
		return saved;
	}

	private WebTestClient.ResponseSpec release(String token, UUID leaseId, String reason) {
		return client.post().uri("/v1/session-leases/" + leaseId + "/release")
				.header("Authorization", "Bearer " + token).contentType(MediaType.APPLICATION_JSON)
				.bodyValue("{\"reason\":\"" + reason + "\"}").exchange();
	}

	private List<AuditEvent> releaseEventsFor(String identity) {
		return auditEvents.findAll().filter(event -> "session_lease.release".equals(event.action()))
				.filter(event -> identity.equals(event.subject())).collectList().block();
	}

	private JsonNode page(String token, String query) {
		byte[] raw = client.get().uri("/v1/session-leases" + query).header("Authorization", "Bearer " + token)
				.exchange().expectStatus().isOk().expectBody().returnResult().getResponseBody();
		return objectMapper.readTree(raw);
	}

	private List<UUID> ids(String token, String query) {
		List<UUID> ids = new ArrayList<>();
		page(token, query).get("items").forEach(item -> ids.add(UUID.fromString(item.get("id").asString())));
		return ids;
	}

	private boolean counting(String token, String query, UUID leaseId) {
		for (JsonNode item : page(token, query).get("items")) {
			if (leaseId.toString().equals(item.get("id").asString())) {
				return item.get("countsTowardCap").asBoolean();
			}
		}
		throw new AssertionError("lease " + leaseId + " missing from " + query);
	}
}
