package io.sessionlayer.controlplane.web;

import static org.assertj.core.api.Assertions.assertThat;

import io.sessionlayer.controlplane.data.config.OperatorSettingsRepository;
import io.sessionlayer.controlplane.data.runtime.AuditEvent;
import io.sessionlayer.controlplane.platform.PlatformPermissions;
import io.sessionlayer.controlplane.support.AbstractConfigApiIT;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.r2dbc.core.DatabaseClient;

class OperatorSettingsCrudIT extends AbstractConfigApiIT {

	@Autowired
	private OperatorSettingsRepository settings;
	@Autowired
	private DatabaseClient db;

	// The singleton is shared context state, so every test restores the cold-start
	// values it started from rather than leaving a ratcheted row behind for the
	// next one.
	@AfterEach
	void resetSingleton() {
		db.sql("UPDATE config.operator_settings SET audit_retention_days = 365, recording_retention_days = 365,"
				+ " default_worm_mode = 'governance', otp_ttl_seconds = 120, default_max_session_seconds = null,"
				+ " default_idle_timeout_seconds = null, default_max_concurrent_sessions = null, origin = 'default'"
				+ " WHERE singleton = true").fetch().rowsUpdated().block();
	}

	private long version() {
		return settings.findSingleton().block().version();
	}

	private Map<String, Object> body(int auditDays, int recordingDays, String worm, int otpTtl) {
		Map<String, Object> body = new HashMap<>();
		body.put("auditRetentionDays", auditDays);
		body.put("recordingRetentionDays", recordingDays);
		body.put("defaultWormMode", worm);
		body.put("otpTtlSeconds", otpTtl);
		body.put("version", version());
		return body;
	}

	@Test
	void getReturnsTheProjectionAndNothingSensitive() {
		String bearer = tokenWith("svc-os-read-" + UUID.randomUUID(), PlatformPermissions.RBAC_READ);

		String raw = client.get().uri("/v1/operator-settings").header("Authorization", "Bearer " + bearer).exchange()
				.expectStatus().isOk().expectBody(String.class).returnResult().getResponseBody();

		client.get().uri("/v1/operator-settings").header("Authorization", "Bearer " + bearer).exchange().expectStatus()
				.isOk().expectBody().jsonPath("$.auditRetentionDays").isEqualTo(365).jsonPath("$.defaultWormMode")
				.isEqualTo("governance").jsonPath("$.defaultCaBackend").isEqualTo("local")
				.jsonPath("$.recordingKeyConfigured").isEqualTo(false).jsonPath("$.deploymentManagedFields").isArray()
				.jsonPath("$.version").exists();

		// Assert on the serialized body: an excluded column would appear as a stray
		// property that no typed getter would ever surface.
		assertThat(raw).doesNotContain("kekReference").doesNotContain("kek_reference")
				.doesNotContain("bootstrapAdminSubject").doesNotContain("bootstrapCredentialHash")
				.doesNotContain("bootstrapCompleted").doesNotContain("recordingStrictDefault")
				.doesNotContain("recordingCustomerPublicKey");
	}

	@Test
	void updatePersistsStampsApiOriginAndAuditsBeforeAfter() {
		String admin = "svc-os-write-" + UUID.randomUUID();
		String bearer = tokenWith(admin, PlatformPermissions.SETTINGS_WRITE, PlatformPermissions.RBAC_READ);
		long before = version();

		client.put().uri("/v1/operator-settings").header("Authorization", "Bearer " + bearer)
				.contentType(MediaType.APPLICATION_JSON).bodyValue(body(400, 500, "compliance", 300)).exchange()
				.expectStatus().isOk().expectBody().jsonPath("$.auditRetentionDays").isEqualTo(400)
				.jsonPath("$.recordingRetentionDays").isEqualTo(500).jsonPath("$.defaultWormMode")
				.isEqualTo("compliance").jsonPath("$.otpTtlSeconds").isEqualTo(300).jsonPath("$.origin")
				.isEqualTo("api").jsonPath("$.version").isEqualTo(before + 1);

		assertThat(settings.findSingleton().block().auditRetentionDays()).isEqualTo(400);

		List<AuditEvent> audit = auditEvents.findByActor(admin).collectList().block();
		assertThat(audit).anySatisfy(e -> {
			assertThat(e.action()).isEqualTo("operator_settings.update");
			assertThat(e.detail().get("before").get("auditRetentionDays").asInt()).isEqualTo(365);
			assertThat(e.detail().get("after").get("auditRetentionDays").asInt()).isEqualTo(400);
			assertThat(e.detail().get("after").get("defaultWormMode").stringValue()).isEqualTo("compliance");
		});
	}

	@Test
	void aStaleVersionIsRefused() {
		String bearer = tokenWith("svc-os-stale-" + UUID.randomUUID(), PlatformPermissions.SETTINGS_WRITE);
		Map<String, Object> stale = body(400, 400, "governance", 120);
		stale.put("version", version() + 7);

		client.put().uri("/v1/operator-settings").header("Authorization", "Bearer " + bearer)
				.contentType(MediaType.APPLICATION_JSON).bodyValue(stale).exchange().expectStatus().isEqualTo(409);
	}

	@Test
	void anUnchangedWriteIsAccepted() {
		String bearer = tokenWith("svc-os-noop-" + UUID.randomUUID(), PlatformPermissions.SETTINGS_WRITE);

		client.put().uri("/v1/operator-settings").header("Authorization", "Bearer " + bearer)
				.contentType(MediaType.APPLICATION_JSON).bodyValue(body(365, 365, "governance", 120)).exchange()
				.expectStatus().isOk();
	}

	@Test
	void shorteningAuditRetentionIsRefused() {
		String bearer = tokenWith("svc-os-audit-" + UUID.randomUUID(), PlatformPermissions.SETTINGS_WRITE);

		client.put().uri("/v1/operator-settings").header("Authorization", "Bearer " + bearer)
				.contentType(MediaType.APPLICATION_JSON).bodyValue(body(364, 365, "governance", 120)).exchange()
				.expectStatus().isEqualTo(422).expectBody().jsonPath("$.detail")
				.value(org.hamcrest.Matchers.containsString("database-owner"));

		assertThat(settings.findSingleton().block().auditRetentionDays()).isEqualTo(365);
	}

	@Test
	void shorteningRecordingRetentionIsRefused() {
		String bearer = tokenWith("svc-os-rec-" + UUID.randomUUID(), PlatformPermissions.SETTINGS_WRITE);

		client.put().uri("/v1/operator-settings").header("Authorization", "Bearer " + bearer)
				.contentType(MediaType.APPLICATION_JSON).bodyValue(body(365, 1, "governance", 120)).exchange()
				.expectStatus().isEqualTo(422);

		assertThat(settings.findSingleton().block().recordingRetentionDays()).isEqualTo(365);
	}

	@Test
	void weakeningTheWormModeIsRefusedButStrengtheningIsAccepted() {
		String bearer = tokenWith("svc-os-worm-" + UUID.randomUUID(), PlatformPermissions.SETTINGS_WRITE);

		client.put().uri("/v1/operator-settings").header("Authorization", "Bearer " + bearer)
				.contentType(MediaType.APPLICATION_JSON).bodyValue(body(365, 365, "compliance", 120)).exchange()
				.expectStatus().isOk();

		client.put().uri("/v1/operator-settings").header("Authorization", "Bearer " + bearer)
				.contentType(MediaType.APPLICATION_JSON).bodyValue(body(365, 365, "governance", 120)).exchange()
				.expectStatus().isEqualTo(422);

		assertThat(settings.findSingleton().block().defaultWormMode()).isEqualTo("compliance");
	}

	@Test
	void rbacReadCannotWriteAndAnUnprivilegedCallerSeesNothing() {
		String readOnly = tokenWith("svc-os-ro-" + UUID.randomUUID(), PlatformPermissions.RBAC_READ);
		String none = tokenWith("svc-os-none-" + UUID.randomUUID());

		client.put().uri("/v1/operator-settings").header("Authorization", "Bearer " + readOnly)
				.contentType(MediaType.APPLICATION_JSON).bodyValue(body(400, 400, "governance", 120)).exchange()
				.expectStatus().isForbidden();
		client.get().uri("/v1/operator-settings").header("Authorization", "Bearer " + none).exchange().expectStatus()
				.isForbidden();
	}
}
