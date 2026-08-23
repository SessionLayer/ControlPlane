package io.sessionlayer.controlplane.recording;

import static org.assertj.core.api.Assertions.assertThat;

import io.sessionlayer.controlplane.api.model.SignedUrl;
import io.sessionlayer.controlplane.data.runtime.AuditEvent;
import io.sessionlayer.controlplane.data.runtime.RecordingRef;
import io.sessionlayer.controlplane.platform.PlatformPermissions;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.Test;

class RecordingReplayIT extends AbstractRecordingIT {

	@Test
	void listFiltersByIdentityAndGetReturnsMetadata() {
		UUID nodeId = seedNode(Map.of("env", "prod"));
		String alice = "alice-" + unique();
		UUID s1 = seedSession(alice, nodeId);
		UUID s2 = seedSession(alice, nodeId);
		RecordingRef r1 = seedRecording(s1, objectKey(s1), "governance", Instant.now().plusSeconds(86_400), false);
		seedRecording(s2, objectKey(s2), "governance", Instant.now().plusSeconds(86_400), false);
		UUID bobSession = seedSession("bob-" + unique(), nodeId);
		seedRecording(bobSession, objectKey(bobSession), "governance", Instant.now().plusSeconds(86_400), false);

		String token = tokenWith("svc-rec-list-" + unique(), PlatformPermissions.RECORDING_REPLAY);
		client.get().uri("/v1/recordings?identity=" + alice).header("Authorization", "Bearer " + token).exchange()
				.expectStatus().isOk().expectBody().jsonPath("$.items.length()").isEqualTo(2);

		client.get().uri("/v1/recordings/" + r1.id()).header("Authorization", "Bearer " + token).exchange()
				.expectStatus().isOk().expectBody().jsonPath("$.identity").isEqualTo(alice).jsonPath("$.wormMode")
				.isEqualTo("governance").jsonPath("$.status").isEqualTo("finalized").jsonPath("$.nodeId")
				.isEqualTo(nodeId.toString());

		client.get().uri("/v1/recordings/" + UUID.randomUUID()).header("Authorization", "Bearer " + token).exchange()
				.expectStatus().isNotFound();
	}

	@Test
	void listRequiresReplayPermission() {
		String token = tokenWith("svc-rec-none-" + unique());
		client.get().uri("/v1/recordings").header("Authorization", "Bearer " + token).exchange().expectStatus()
				.isForbidden();
	}

	@Test
	void replayIssuesShortLivedSignedUrlToTheEncryptedObject() throws Exception {
		UUID nodeId = seedNode(Map.of("env", "prod"));
		UUID sessionId = seedSession("carol-" + unique(), nodeId);
		String key = objectKey(sessionId);
		byte[] ciphertext = ("SLREC1-sealed-" + UUID.randomUUID()).getBytes();
		putObject(key, "governance", ciphertext);
		RecordingRef ref = seedRecording(sessionId, key, "governance", Instant.now().plusSeconds(86_400), false);

		String svc = "svc-rec-replay-" + unique();
		String token = tokenWith(svc, PlatformPermissions.RECORDING_REPLAY);
		var result = client.post().uri("/v1/recordings/" + ref.id() + "/replay")
				.header("Authorization", "Bearer " + token).exchange().expectStatus().isOk().expectBody(SignedUrl.class)
				.returnResult();
		SignedUrl signed = result.getResponseBody();

		assertThat(signed.getMethod()).isEqualTo("GET");
		long ttlSeconds = signed.getExpiresAt().toInstant().getEpochSecond() - Instant.now().getEpochSecond();
		assertThat(ttlSeconds).isBetween(240L, 360L);

		String body = new String(result.getResponseBodyContent());
		assertThat(body).doesNotContain(new String(ciphertext));

		assertThat(fetch(signed.getUrl().toString())).isEqualTo(ciphertext);

		List<AuditEvent> events = auditEvents.findByActor(svc).collectList().block();
		assertThat(events).anySatisfy(e -> {
			assertThat(e.action()).isEqualTo("recording.replay");
			assertThat(e.correlationId()).isEqualTo(sessionId);
			assertThat(e.accessModel()).isEqualTo("standing");
			assertThat(e.nodeLabels().get("env").stringValue()).isEqualTo("prod");
		});
	}

	@Test
	void exportIssuesSignedUrlUnderExportPermission() throws Exception {
		UUID nodeId = seedNode(Map.of("env", "prod"));
		UUID sessionId = seedSession("dave-" + unique(), nodeId);
		String key = objectKey(sessionId);
		putObject(key, "governance", "sealed".getBytes());
		RecordingRef ref = seedRecording(sessionId, key, "governance", Instant.now().plusSeconds(86_400), false);

		String svc = "svc-rec-export-" + unique();
		String token = tokenWith(svc, PlatformPermissions.RECORDING_EXPORT);
		client.post().uri("/v1/recordings/" + ref.id() + "/export").header("Authorization", "Bearer " + token)
				.exchange().expectStatus().isOk().expectBody().jsonPath("$.method").isEqualTo("GET").jsonPath("$.url")
				.exists();

		assertThat(auditEvents.findByActor(svc).collectList().block())
				.anySatisfy(e -> assertThat(e.action()).isEqualTo("recording.export"));
	}

	@Test
	void outOfScopeReplayIsForbidden() {
		UUID nodeId = seedNode(Map.of("env", "prod"));
		UUID sessionId = seedSession("erin-" + unique(), nodeId);
		RecordingRef ref = seedRecording(sessionId, objectKey(sessionId), "governance",
				Instant.now().plusSeconds(86_400), false);

		String token = tokenScoped("svc-rec-oos-" + unique(), nodeLabelScope("env", "staging"),
				PlatformPermissions.RECORDING_REPLAY);
		client.post().uri("/v1/recordings/" + ref.id() + "/replay").header("Authorization", "Bearer " + token)
				.exchange().expectStatus().isForbidden();
	}

	@Test
	void inScopeReplayIsAllowed() throws Exception {
		UUID nodeId = seedNode(Map.of("env", "prod"));
		UUID sessionId = seedSession("frank-" + unique(), nodeId);
		String key = objectKey(sessionId);
		putObject(key, "governance", "sealed".getBytes());
		RecordingRef ref = seedRecording(sessionId, key, "governance", Instant.now().plusSeconds(86_400), false);

		String token = tokenScoped("svc-rec-ins-" + unique(), nodeLabelScope("env", "prod"),
				PlatformPermissions.RECORDING_REPLAY);
		client.post().uri("/v1/recordings/" + ref.id() + "/replay").header("Authorization", "Bearer " + token)
				.exchange().expectStatus().isOk();
	}

	@Test
	void replayOfPrunedRecordingIsConflict() {
		UUID nodeId = seedNode(Map.of("env", "prod"));
		UUID sessionId = seedSession("grace-" + unique(), nodeId);
		RecordingRef ref = RecordingRef.begin(UUID.randomUUID(), sessionId, objectKey(sessionId), "kms://customer-1",
				"governance", Instant.now().plusSeconds(86_400)).pruned("governance", "someone", Instant.now());
		recordings.save(ref).block();

		String token = tokenWith("svc-rec-pruned-" + unique(), PlatformPermissions.RECORDING_REPLAY);
		client.post().uri("/v1/recordings/" + ref.id() + "/replay").header("Authorization", "Bearer " + token)
				.exchange().expectStatus().isEqualTo(409);
	}

	@Test
	void replayOfNonFinalizedRecordingIsConflict() {
		UUID nodeId = seedNode(Map.of("env", "prod"));
		UUID sessionId = seedSession("henry-" + unique(), nodeId);
		RecordingRef ref = seedRecording(sessionId, objectKey(sessionId), "governance",
				Instant.now().plusSeconds(86_400), false, "recording");

		String token = tokenWith("svc-rec-nf-" + unique(), PlatformPermissions.RECORDING_REPLAY);
		client.post().uri("/v1/recordings/" + ref.id() + "/replay").header("Authorization", "Bearer " + token)
				.exchange().expectStatus().isEqualTo(409);
	}

	@Test
	void probeWithoutAnyRecordingPermissionIsForbiddenAndAudited() {
		UUID nodeId = seedNode(Map.of("env", "prod"));
		UUID sessionId = seedSession("ivy-" + unique(), nodeId);
		RecordingRef ref = seedRecording(sessionId, objectKey(sessionId), "governance",
				Instant.now().plusSeconds(86_400), false);

		String svc = "svc-rec-noperm-" + unique();
		String token = tokenWith(svc);
		client.post().uri("/v1/recordings/" + ref.id() + "/replay").header("Authorization", "Bearer " + token)
				.exchange().expectStatus().isForbidden();
		client.post().uri("/v1/recordings/" + UUID.randomUUID() + "/replay").header("Authorization", "Bearer " + token)
				.exchange().expectStatus().isForbidden(); // absent id: SAME 403, no oracle

		assertThat(auditEvents.findByActor(svc).collectList().block()).anySatisfy(e -> {
			assertThat(e.action()).isEqualTo("recording.replay");
			assertThat(e.outcome()).isEqualTo("denied");
		});
	}
}
