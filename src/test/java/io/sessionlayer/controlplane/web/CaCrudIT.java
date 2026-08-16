package io.sessionlayer.controlplane.web;

import static org.assertj.core.api.Assertions.assertThat;

import io.sessionlayer.controlplane.data.config.CaConfig;
import io.sessionlayer.controlplane.data.config.CaConfigRepository;
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
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

class CaCrudIT extends AbstractConfigApiIT {

	@Autowired
	private CaConfigRepository caConfigs;

	// Azure enabled (this class only, additively over AbstractAuthIT's own
	// @DynamicPropertySource) so the write-path keyReference checks below exercise
	// the real KeyVaultKeyReference.parse gate in CaConfigService.validate rather
	// than the "not configured" branch. No network call happens at bean
	// construction (AzureKeyVaultSignerFactory resolves the credential chain
	// lazily), so this is safe without real Azure credentials.
	@DynamicPropertySource
	static void azureProperties(DynamicPropertyRegistry registry) {
		registry.add("sessionlayer.ca.azure.enabled", () -> "true");
		registry.add("sessionlayer.ca.azure.vault-uri", () -> "https://sl.vault.azure.net");
	}

	// deleteAll is safe here only because the AbstractAuthIT context disables
	// cold-start + the mTLS server (so nothing else provisions a ca_config row) and
	// Failsafe runs ITs serially; the data-layer suites use a separate container.
	@AfterEach
	void resetCas() {
		caConfigs.deleteAll().block();
	}

	private Map<String, Object> caBody(String name, String kind, String backend, String keyReference,
			String algorithm) {
		Map<String, Object> body = new HashMap<>();
		body.put("name", name);
		body.put("caKind", kind);
		body.put("backend", backend);
		body.put("keyReference", keyReference);
		body.put("algorithm", algorithm);
		return body;
	}

	@Test
	void createValidatesPersistsAndAudits() {
		String admin = "svc-ca-admin-" + UUID.randomUUID();
		String token = tokenWith(admin, PlatformPermissions.CA_MANAGE);
		String name = "ca-" + UUID.randomUUID();

		client.post().uri("/v1/cas").header("Authorization", "Bearer " + token).contentType(MediaType.APPLICATION_JSON)
				.bodyValue(caBody(name, "user", "local", "local:handle-" + UUID.randomUUID(), "ecdsa-p256")).exchange()
				.expectStatus().isCreated().expectBody().jsonPath("$.id").isNotEmpty().jsonPath("$.name")
				.isEqualTo(name).jsonPath("$.caKind").isEqualTo("user").jsonPath("$.backend").isEqualTo("local")
				.jsonPath("$.algorithm").isEqualTo("ecdsa-p256").jsonPath("$.origin").isEqualTo("api")
				.jsonPath("$.rotationState").isEqualTo("active").jsonPath("$.version").isEqualTo(0);

		client.get().uri("/v1/cas").header("Authorization", "Bearer " + token).exchange().expectStatus().isOk()
				.expectBody().jsonPath("$.items").isArray();
		List<AuditEvent> audit = auditEvents.findByActor(admin).collectList().block();
		assertThat(audit).anySatisfy(e -> assertThat(e.action()).isEqualTo("ca.create"));
	}

	@Test
	void privateKeyMaterialRejectedPreCommit() {
		String token = tokenWith("svc-ca-priv-" + UUID.randomUUID(), PlatformPermissions.CA_MANAGE);

		client.post().uri("/v1/cas").header("Authorization", "Bearer " + token).contentType(MediaType.APPLICATION_JSON)
				.bodyValue(caBody("ca-" + UUID.randomUUID(), "user", "local",
						"-----BEGIN PRIVATE KEY-----\nMIIB...\n-----END PRIVATE KEY-----", "ecdsa-p256"))
				.exchange().expectStatus().isEqualTo(422).expectHeader()
				.contentTypeCompatibleWith(MediaType.APPLICATION_PROBLEM_JSON).expectBody().jsonPath("$.title")
				.isEqualTo("Invalid configuration").jsonPath("$.type")
				.isEqualTo("https://docs.sessionlayer.example/problems/validation-error");
	}

	@Test
	void azureKeyvaultWithEd25519RejectedPreCommit() {
		String token = tokenWith("svc-ca-d6-" + UUID.randomUUID(), PlatformPermissions.CA_MANAGE);

		// Azure Key Vault has no Ed25519 key type -> 422. azure_keyvault
		// itself is a real, signer-backed backend now, so this must fail on the
		// algorithm, not on "no signer in this build" (that would mean the backend
		// capability flip regressed).
		client.post().uri("/v1/cas").header("Authorization", "Bearer " + token).contentType(MediaType.APPLICATION_JSON)
				.bodyValue(
						caBody("ca-" + UUID.randomUUID(), "user", "azure_keyvault", "azurekv://vault/key", "ed25519"))
				.exchange().expectStatus().isEqualTo(422).expectBody().jsonPath("$.title")
				.isEqualTo("Invalid configuration").jsonPath("$.detail").value(detail -> assertThat((String) detail)
						.contains("ed25519").doesNotContain("no signer in this build"));
	}

	@Test
	void manageGatesWritesAndReadsRotateNeedsCaRotate() {
		String noneToken = tokenWith("svc-ca-none-" + UUID.randomUUID());
		client.post().uri("/v1/cas").header("Authorization", "Bearer " + noneToken)
				.contentType(MediaType.APPLICATION_JSON)
				.bodyValue(caBody("ca-" + UUID.randomUUID(), "user", "local", "local:x", "ecdsa-p256")).exchange()
				.expectStatus().isForbidden();
		client.get().uri("/v1/cas").header("Authorization", "Bearer " + noneToken).exchange().expectStatus()
				.isForbidden();

		String rotateOnly = tokenWith("svc-ca-rot-" + UUID.randomUUID(), PlatformPermissions.CA_ROTATE);
		client.post().uri("/v1/cas").header("Authorization", "Bearer " + rotateOnly)
				.contentType(MediaType.APPLICATION_JSON)
				.bodyValue(caBody("ca-" + UUID.randomUUID(), "user", "local", "local:x", "ecdsa-p256")).exchange()
				.expectStatus().isForbidden();
		client.get().uri("/v1/cas").header("Authorization", "Bearer " + rotateOnly).exchange().expectStatus()
				.isForbidden();

		String manage = tokenWith("svc-ca-mng-" + UUID.randomUUID(), PlatformPermissions.CA_MANAGE);
		client.get().uri("/v1/cas").header("Authorization", "Bearer " + manage).exchange().expectStatus().isOk();
		client.post().uri("/v1/cas/" + UUID.randomUUID() + "/rotate").header("Authorization", "Bearer " + manage)
				.contentType(MediaType.APPLICATION_JSON).bodyValue(Map.of()).exchange().expectStatus().isForbidden();
	}

	@Test
	void getUpdateRoundTripWithOptimisticConcurrency() {
		String token = tokenWith("svc-ca-rt-" + UUID.randomUUID(), PlatformPermissions.CA_MANAGE);
		String name = "ca-" + UUID.randomUUID();
		String id = create(token, caBody(name, "session", "local", "local:seed", "ecdsa-p256"));

		client.get().uri("/v1/cas/" + id).header("Authorization", "Bearer " + token).exchange().expectStatus().isOk()
				.expectBody().jsonPath("$.backend").isEqualTo("local").jsonPath("$.algorithm").isEqualTo("ecdsa-p256");

		client.put().uri("/v1/cas/" + id).header("Authorization", "Bearer " + token)
				.contentType(MediaType.APPLICATION_JSON)
				.bodyValue(Map.of("backend", "local", "keyReference", "local:rotated", "algorithm", "ecdsa-p384",
						"version", 0))
				.exchange().expectStatus().isEqualTo(409).expectBody().jsonPath("$.detail")
				.value(detail -> assertThat((String) detail).contains("/v1/cas/{caId}/rotate"));

		client.get().uri("/v1/cas/" + id).header("Authorization", "Bearer " + token).exchange().expectStatus().isOk()
				.expectBody().jsonPath("$.backend").isEqualTo("local").jsonPath("$.keyReference")
				.isEqualTo("local:seed").jsonPath("$.algorithm").isEqualTo("ecdsa-p256").jsonPath("$.version")
				.isEqualTo(0);

		// A non-active row (seeded directly; the API only ever mints active CAs) is
		// not signing, so it keeps the coverage the guard above necessarily removes
		// from the active case: PUT still round-trips backend/keyReference/algorithm
		// with optimistic concurrency intact.
		CaConfig outgoing = caConfigs.save(CaConfig.create("ca-outgoing-" + UUID.randomUUID(), "session", "local",
				"local:outgoing-seed", "ecdsa-p256", "outgoing", "default")).block();

		client.put().uri("/v1/cas/" + outgoing.id()).header("Authorization", "Bearer " + token)
				.contentType(MediaType.APPLICATION_JSON)
				.bodyValue(Map.of("backend", "local", "keyReference", "local:outgoing-rotated", "algorithm",
						"ecdsa-p384", "version", 0))
				.exchange().expectStatus().isOk().expectBody().jsonPath("$.backend").isEqualTo("local")
				.jsonPath("$.algorithm").isEqualTo("ecdsa-p384").jsonPath("$.keyReference")
				.isEqualTo("local:outgoing-rotated").jsonPath("$.rotationState").isEqualTo("outgoing")
				.jsonPath("$.origin").isEqualTo("api").jsonPath("$.version").isEqualTo(1);

		client.put().uri("/v1/cas/" + outgoing.id()).header("Authorization", "Bearer " + token)
				.contentType(MediaType.APPLICATION_JSON)
				.bodyValue(
						Map.of("backend", "local", "keyReference", "local:z", "algorithm", "ecdsa-p256", "version", 0))
				.exchange().expectStatus().isEqualTo(409);
	}

	@Test
	void azureKeyvaultKeyReferenceRejectedAtTheWritePath() {
		String token = tokenWith("svc-ca-azkv-ref-" + UUID.randomUUID(), PlatformPermissions.CA_MANAGE);

		// No fourth path segment at all -> refused as version-less, not resolved to
		// whatever Key Vault would treat as "latest".
		client.post().uri("/v1/cas").header("Authorization", "Bearer " + token).contentType(MediaType.APPLICATION_JSON)
				.bodyValue(caBody("ca-" + UUID.randomUUID(), "user", "azure_keyvault",
						"https://sl.vault.azure.net/keys/session-ca", "ecdsa-p256"))
				.exchange().expectStatus().isEqualTo(422).expectBody().jsonPath("$.detail")
				.value(detail -> assertThat((String) detail).contains("version"));

		client.post().uri("/v1/cas").header("Authorization", "Bearer " + token).contentType(MediaType.APPLICATION_JSON)
				.bodyValue(caBody("ca-" + UUID.randomUUID(), "host", "azure_keyvault",
						"https://someone-elses-vault.vault.azure.net/keys/k/0123456789abcdef0123456789abcdef",
						"ecdsa-p256"))
				.exchange().expectStatus().isEqualTo(422).expectBody().jsonPath("$.detail")
				.value(detail -> assertThat((String) detail).contains("not the configured Key Vault"));
	}

	@Test
	void p521IsCreatableAndAnUnsignableAlgorithmIsRefused() {
		String token = tokenWith("svc-ca-alg-" + UUID.randomUUID(), PlatformPermissions.CA_MANAGE);

		client.post().uri("/v1/cas").header("Authorization", "Bearer " + token).contentType(MediaType.APPLICATION_JSON)
				.bodyValue(caBody("ca-" + UUID.randomUUID(), "user", "local", "local:p521", "ecdsa-p521")).exchange()
				.expectStatus().isCreated().expectBody().jsonPath("$.algorithm").isEqualTo("ecdsa-p521");

		client.post().uri("/v1/cas").header("Authorization", "Bearer " + token).contentType(MediaType.APPLICATION_JSON)
				.bodyValue(caBody("ca-" + UUID.randomUUID(), "host", "local", "local:ed", "ed25519")).exchange()
				.expectStatus().isEqualTo(422).expectBody().jsonPath("$.detail")
				.value(detail -> assertThat((String) detail).contains("ed25519"));
	}

	@Test
	void deleteRefusesActiveButDeletesNonActive() {
		String token = tokenWith("svc-ca-del-" + UUID.randomUUID(), PlatformPermissions.CA_MANAGE);

		CaConfig expired = caConfigs.save(CaConfig.create("ca-exp-" + UUID.randomUUID(), "host", "local", "local:old",
				"ecdsa-p256", "expired", "default")).block();
		String activeId = create(token, caBody("ca-" + UUID.randomUUID(), "host", "local", "local:new", "ecdsa-p256"));

		client.delete().uri("/v1/cas/" + activeId).header("Authorization", "Bearer " + token).exchange().expectStatus()
				.isEqualTo(409);

		client.delete().uri("/v1/cas/" + expired.id()).header("Authorization", "Bearer " + token).exchange()
				.expectStatus().isNoContent();
		client.delete().uri("/v1/cas/" + expired.id()).header("Authorization", "Bearer " + token).exchange()
				.expectStatus().isNoContent();
		client.get().uri("/v1/cas/" + expired.id()).header("Authorization", "Bearer " + token).exchange().expectStatus()
				.isNotFound();
	}

	@Test
	void idempotencyKeyReplaysAndRejectsBodyChange() {
		String token = tokenWith("svc-ca-idem-" + UUID.randomUUID(), PlatformPermissions.CA_MANAGE);
		String name = "ca-" + UUID.randomUUID();
		String key = "idem-" + UUID.randomUUID();
		Map<String, Object> body = caBody(name, "user", "local", "local:idem", "ecdsa-p256");

		String firstId = client.post().uri("/v1/cas").header("Authorization", "Bearer " + token)
				.header("Idempotency-Key", key).contentType(MediaType.APPLICATION_JSON).bodyValue(body).exchange()
				.expectStatus().isCreated().returnResult(Map.class).getResponseBody().blockFirst().get("id").toString();

		// Same key + body -> the original response replayed (a real second create would
		// 409 on the active-per-kind index).
		String replayId = client.post().uri("/v1/cas").header("Authorization", "Bearer " + token)
				.header("Idempotency-Key", key).contentType(MediaType.APPLICATION_JSON).bodyValue(body).exchange()
				.expectStatus().isCreated().returnResult(Map.class).getResponseBody().blockFirst().get("id").toString();
		assertThat(replayId).isEqualTo(firstId);

		client.post().uri("/v1/cas").header("Authorization", "Bearer " + token).header("Idempotency-Key", key)
				.contentType(MediaType.APPLICATION_JSON)
				.bodyValue(caBody(name, "user", "local", "local:different", "ecdsa-p256")).exchange().expectStatus()
				.isEqualTo(422).expectBody().jsonPath("$.type")
				.isEqualTo("https://docs.sessionlayer.example/problems/idempotency-key-conflict");
	}

	@Test
	void cursorPaginationReturnsAStableForwardCursor() {
		String token = tokenWith("svc-ca-page-" + UUID.randomUUID(), PlatformPermissions.CA_MANAGE);
		// Seed non-active rows (no active-per-kind constraint) so several CAs coexist.
		for (int i = 0; i < 3; i++) {
			caConfigs.save(CaConfig.create("ca-page-" + UUID.randomUUID(), "host", "local", "local:p" + i, "ecdsa-p256",
					"expired", "default")).block();
		}

		@SuppressWarnings("unchecked")
		Map<String, Object> page1 = client.get().uri("/v1/cas?limit=2").header("Authorization", "Bearer " + token)
				.exchange().expectStatus().isOk().returnResult(Map.class).getResponseBody().blockFirst();
		List<Map<String, Object>> items1 = (List<Map<String, Object>>) page1.get("items");
		assertThat(items1).hasSize(2);
		String next = (String) page1.get("nextCursor");
		assertThat(next).isNotBlank();

		@SuppressWarnings("unchecked")
		Map<String, Object> page2 = client.get().uri("/v1/cas?limit=2&cursor=" + next)
				.header("Authorization", "Bearer " + token).exchange().expectStatus().isOk().returnResult(Map.class)
				.getResponseBody().blockFirst();
		List<Map<String, Object>> items2 = (List<Map<String, Object>>) page2.get("items");
		assertThat(items2).isNotEmpty();
		List<Object> ids1 = items1.stream().map(m -> m.get("id")).toList();
		assertThat(items2.stream().map(m -> m.get("id"))).noneMatch(ids1::contains);

		client.get().uri("/v1/cas?cursor=not-a-cursor").header("Authorization", "Bearer " + token).exchange()
				.expectStatus().isBadRequest();
	}

	@Test
	void rotateProducesNewActiveWithoutLeakingPrivateMaterial() {
		String admin = "svc-ca-rotate-" + UUID.randomUUID();
		String token = tokenWith(admin, PlatformPermissions.CA_MANAGE, PlatformPermissions.CA_ROTATE);
		String id = create(token, caBody("ca-" + UUID.randomUUID(), "session", "local", "local:seed", "ecdsa-p256"));

		client.post().uri("/v1/cas/" + id + "/rotate").header("Authorization", "Bearer " + token)
				.contentType(MediaType.APPLICATION_JSON).bodyValue(Map.of()).exchange().expectStatus().isOk()
				.expectBody().jsonPath("$.caKind").isEqualTo("session").jsonPath("$.rotationState").isEqualTo("active")
				.jsonPath("$.id").value(newId -> assertThat(newId).isNotEqualTo(id))
				.jsonPath("$.keyReference").value(ref -> assertThat((String) ref).doesNotContain("PRIVATE KEY"));

		client.get().uri("/v1/cas/" + id).header("Authorization", "Bearer " + token).exchange().expectStatus().isOk()
				.expectBody().jsonPath("$.rotationState").isEqualTo("outgoing");
		List<AuditEvent> audit = auditEvents.findByActor(admin).collectList().block();
		assertThat(audit).anySatisfy(e -> assertThat(e.action()).isEqualTo("ca.rotate"));

		String manageOnly = tokenWith("svc-ca-mng2-" + UUID.randomUUID(), PlatformPermissions.CA_MANAGE);
		client.post().uri("/v1/cas/" + id + "/rotate").header("Authorization", "Bearer " + manageOnly)
				.contentType(MediaType.APPLICATION_JSON).bodyValue(Map.of()).exchange().expectStatus().isForbidden();
	}

	private String create(String token, Map<String, Object> body) {
		return client.post().uri("/v1/cas").header("Authorization", "Bearer " + token)
				.contentType(MediaType.APPLICATION_JSON).bodyValue(body).exchange().expectStatus().isCreated()
				.returnResult(Map.class).getResponseBody().blockFirst().get("id").toString();
	}
}
