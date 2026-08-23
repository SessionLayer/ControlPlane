package io.sessionlayer.controlplane.web;

import static org.assertj.core.api.Assertions.assertThat;

import io.sessionlayer.controlplane.bootstrap.BootstrapService;
import io.sessionlayer.controlplane.data.config.OperatorSettingsRepository;
import io.sessionlayer.controlplane.platform.PlatformPermissions;
import io.sessionlayer.controlplane.support.AbstractConfigApiIT;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;

/**
 * The boot-reconciliation interaction. {@code default-max-concurrent} is pinned
 * by a deployment property here, so the API must refuse a change to it rather
 * than accept a write that {@code reconcileSessionLimitDefaults} would revert
 * at the next restart. The two unpinned siblings stay writable and must survive
 * a reconciliation.
 */
@SpringBootTest(properties = {"sessionlayer.mtls.server.port=0", "sessionlayer.auth.token-endpoint.max=1000000",
		"sessionlayer.session-limits.default-max-concurrent=4"})
class OperatorSettingsPinnedFieldIT extends AbstractConfigApiIT {

	@Autowired
	private OperatorSettingsRepository settings;
	@Autowired
	private BootstrapService bootstrap;

	private long version() {
		return settings.findSingleton().block().version();
	}

	private Map<String, Object> body(Integer maxConcurrent, Integer maxSeconds, Integer idleSeconds) {
		Map<String, Object> body = new HashMap<>();
		body.put("auditRetentionDays", 365);
		body.put("recordingRetentionDays", 365);
		body.put("defaultWormMode", "governance");
		body.put("otpTtlSeconds", 120);
		if (maxConcurrent != null) {
			body.put("defaultMaxConcurrentSessions", maxConcurrent);
		}
		if (maxSeconds != null) {
			body.put("defaultMaxSessionSeconds", maxSeconds);
		}
		if (idleSeconds != null) {
			body.put("defaultIdleTimeoutSeconds", idleSeconds);
		}
		body.put("version", version());
		return body;
	}

	@Test
	void getReportsThePinnedFieldAndOnlyThatOne() {
		String bearer = tokenWith("svc-pin-read-" + UUID.randomUUID(), PlatformPermissions.RBAC_READ);

		client.get().uri("/v1/operator-settings").header("Authorization", "Bearer " + bearer).exchange().expectStatus()
				.isOk().expectBody().jsonPath("$.deploymentManagedFields")
				.isEqualTo(java.util.List.of("defaultMaxConcurrentSessions")).jsonPath("$.defaultMaxConcurrentSessions")
				.isEqualTo(4);
	}

	@Test
	void changingThePinnedFieldIsRefusedAndNamesTheProperty() {
		String bearer = tokenWith("svc-pin-write-" + UUID.randomUUID(), PlatformPermissions.SETTINGS_WRITE);

		client.put().uri("/v1/operator-settings").header("Authorization", "Bearer " + bearer)
				.contentType(MediaType.APPLICATION_JSON).bodyValue(body(9, null, null)).exchange().expectStatus()
				.isEqualTo(422).expectBody().jsonPath("$.detail")
				.value(org.hamcrest.Matchers.containsString("sessionlayer.session-limits.default-max-concurrent"));

		assertThat(settings.findSingleton().block().defaultMaxConcurrentSessions()).isEqualTo(4);
	}

	// Omission clears a nullable field, so leaving a pinned field out is a change
	// too - the failure this refusal exists to prevent, since it would look like a
	// successful write and revert at the next boot.
	@Test
	void omittingThePinnedFieldIsAlsoRefused() {
		String bearer = tokenWith("svc-pin-omit-" + UUID.randomUUID(), PlatformPermissions.SETTINGS_WRITE);

		client.put().uri("/v1/operator-settings").header("Authorization", "Bearer " + bearer)
				.contentType(MediaType.APPLICATION_JSON).bodyValue(body(null, 3600, null)).exchange().expectStatus()
				.isEqualTo(422);

		assertThat(settings.findSingleton().block().defaultMaxConcurrentSessions()).isEqualTo(4);
	}

	@Test
	void echoingThePinnedFieldUnchangedIsAcceptedAndTheUnpinnedSiblingsSurviveReconciliation() {
		String bearer = tokenWith("svc-pin-echo-" + UUID.randomUUID(), PlatformPermissions.SETTINGS_WRITE);

		client.put().uri("/v1/operator-settings").header("Authorization", "Bearer " + bearer)
				.contentType(MediaType.APPLICATION_JSON).bodyValue(body(4, 7200, 900)).exchange().expectStatus().isOk()
				.expectBody().jsonPath("$.defaultMaxSessionSeconds").isEqualTo(7200)
				.jsonPath("$.defaultIdleTimeoutSeconds").isEqualTo(900);

		// Boot reconciliation is the thing that would silently revert an accepted
		// write; run it and prove the unpinned values are still there.
		bootstrap.runAtStartup().block();

		var reconciled = settings.findSingleton().block();
		assertThat(reconciled.defaultMaxSessionSeconds()).isEqualTo(7200);
		assertThat(reconciled.defaultIdleTimeoutSeconds()).isEqualTo(900);
		assertThat(reconciled.defaultMaxConcurrentSessions()).isEqualTo(4);
	}
}
