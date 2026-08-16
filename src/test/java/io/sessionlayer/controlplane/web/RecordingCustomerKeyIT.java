package io.sessionlayer.controlplane.web;

import static org.assertj.core.api.Assertions.assertThat;

import io.sessionlayer.controlplane.data.config.OperatorSettingsRepository;
import io.sessionlayer.controlplane.data.runtime.AuditEvent;
import io.sessionlayer.controlplane.platform.PlatformPermissions;
import io.sessionlayer.controlplane.support.AbstractConfigApiIT;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.spec.ECGenParameterSpec;
import java.util.Base64;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.r2dbc.core.DatabaseClient;

class RecordingCustomerKeyIT extends AbstractConfigApiIT {

	@Autowired
	private OperatorSettingsRepository settings;
	@Autowired
	private DatabaseClient db;

	@AfterEach
	void clearProvisionedKey() {
		db.sql("UPDATE config.operator_settings SET recording_customer_public_key = null, recording_key_ref = null,"
				+ " recording_key_seal_algorithm = 'ecies_p256' WHERE singleton = true").fetch().rowsUpdated().block();
	}

	private long version() {
		return settings.findSingleton().block().version();
	}

	private Map<String, Object> keyBody(String base64Key, String algorithm) {
		Map<String, Object> body = new HashMap<>();
		body.put("publicKey", base64Key);
		body.put("sealAlgorithm", algorithm);
		body.put("version", version());
		return body;
	}

	private static KeyPair ec(String curve) throws Exception {
		KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
		generator.initialize(new ECGenParameterSpec(curve));
		return generator.generateKeyPair();
	}

	private static String spki(KeyPair pair) {
		return Base64.getEncoder().encodeToString(pair.getPublic().getEncoded());
	}

	private static String fingerprint(KeyPair pair) throws Exception {
		return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(pair.getPublic().getEncoded()));
	}

	@Test
	void anUnprovisionedKeyIsConfiguredFalseRatherThanNotFound() {
		String bearer = tokenWith("svc-rk-empty-" + UUID.randomUUID(), PlatformPermissions.RBAC_READ);

		client.get().uri("/v1/operator-settings/recording-customer-key").header("Authorization", "Bearer " + bearer)
				.exchange().expectStatus().isOk().expectBody().jsonPath("$.configured").isEqualTo(false)
				.jsonPath("$.publicKey").doesNotExist().jsonPath("$.fingerprintSha256").doesNotExist();
	}

	@Test
	void firstProvisioningSucceedsAndAuditsFingerprintsOnly() throws Exception {
		String admin = "svc-rk-provision-" + UUID.randomUUID();
		String bearer = tokenWith(admin, PlatformPermissions.RECORDING_KEY_MANAGE, PlatformPermissions.RBAC_READ);
		KeyPair pair = ec("secp256r1");
		Map<String, Object> body = keyBody(spki(pair), "ecies_p256");
		body.put("keyRef", "vault://customer/recording-key");

		client.put().uri("/v1/operator-settings/recording-customer-key").header("Authorization", "Bearer " + bearer)
				.contentType(MediaType.APPLICATION_JSON).bodyValue(body).exchange().expectStatus().isOk().expectBody()
				.jsonPath("$.configured").isEqualTo(true).jsonPath("$.publicKey").isEqualTo(spki(pair))
				.jsonPath("$.sealAlgorithm").isEqualTo("ecies_p256").jsonPath("$.keyRef")
				.isEqualTo("vault://customer/recording-key").jsonPath("$.fingerprintSha256")
				.isEqualTo(fingerprint(pair));

		assertThat(settings.findSingleton().block().recordingCustomerPublicKey())
				.isEqualTo(pair.getPublic().getEncoded());

		List<AuditEvent> audit = auditEvents.findByActor(admin).collectList().block();
		assertThat(audit).anySatisfy(e -> {
			assertThat(e.action()).isEqualTo("operator_settings.recording_key.provision");
			assertThat(e.detail().get("before")).isNull();
			assertThat(e.detail().get("after").get("fingerprintSha256").stringValue()).isEqualTo(fingerprint(pair));
			assertThat(e.detail().toString()).doesNotContain(spki(pair));
		});
	}

	@Test
	void theSettingsVersionIncrementsByExactlyOne() throws Exception {
		String bearer = tokenWith("svc-rk-version-" + UUID.randomUUID(), PlatformPermissions.RECORDING_KEY_MANAGE);
		long before = version();

		client.put().uri("/v1/operator-settings/recording-customer-key").header("Authorization", "Bearer " + bearer)
				.contentType(MediaType.APPLICATION_JSON).bodyValue(keyBody(spki(ec("secp256r1")), "ecies_p256"))
				.exchange().expectStatus().isOk();

		assertThat(version()).isEqualTo(before + 1);
	}

	@Test
	void aPkcs8PrivateKeyIsNamedAsPrivateKeyMaterial() throws Exception {
		String bearer = tokenWith("svc-rk-pkcs8-" + UUID.randomUUID(), PlatformPermissions.RECORDING_KEY_MANAGE);
		String pkcs8 = Base64.getEncoder().encodeToString(ec("secp256r1").getPrivate().getEncoded());

		client.put().uri("/v1/operator-settings/recording-customer-key").header("Authorization", "Bearer " + bearer)
				.contentType(MediaType.APPLICATION_JSON).bodyValue(keyBody(pkcs8, "ecies_p256")).exchange()
				.expectStatus().isEqualTo(422).expectBody().jsonPath("$.detail")
				.value(org.hamcrest.Matchers.containsString("private key material"));

		assertThat(settings.findSingleton().block().recordingCustomerPublicKey()).isNull();
	}

	@Test
	void aSec1EcPrivateKeyIsNamedAsPrivateKeyMaterial() throws Exception {
		String bearer = tokenWith("svc-rk-sec1-" + UUID.randomUUID(), PlatformPermissions.RECORDING_KEY_MANAGE);
		// The bare SEC1 ECPrivateKey (RFC 5915) that lives inside the PKCS#8 wrapper —
		// what `openssl ecparam -genkey` writes under `BEGIN EC PRIVATE KEY`, and a
		// shape CustomerPublicKeys alone would only call "not a public key".
		byte[] sec1 = org.bouncycastle.asn1.pkcs.PrivateKeyInfo.getInstance(ec("secp256r1").getPrivate().getEncoded())
				.parsePrivateKey().toASN1Primitive().getEncoded();

		client.put().uri("/v1/operator-settings/recording-customer-key").header("Authorization", "Bearer " + bearer)
				.contentType(MediaType.APPLICATION_JSON)
				.bodyValue(keyBody(Base64.getEncoder().encodeToString(sec1), "ecies_p256")).exchange().expectStatus()
				.isEqualTo(422).expectBody().jsonPath("$.detail")
				.value(org.hamcrest.Matchers.containsString("private key material"));
	}

	@Test
	void aPemBlobIsNamedAsPrivateKeyMaterial() {
		String bearer = tokenWith("svc-rk-pem-" + UUID.randomUUID(), PlatformPermissions.RECORDING_KEY_MANAGE);
		String pem = "-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqG\n-----END PRIVATE KEY-----";

		client.put().uri("/v1/operator-settings/recording-customer-key").header("Authorization", "Bearer " + bearer)
				.contentType(MediaType.APPLICATION_JSON).bodyValue(keyBody(pem, "ecies_p256")).exchange().expectStatus()
				.isEqualTo(422).expectBody().jsonPath("$.detail")
				.value(org.hamcrest.Matchers.containsString("private key material"));
	}

	@Test
	void anRsaKeySubmittedAsEciesP256IsRefused() throws Exception {
		String bearer = tokenWith("svc-rk-rsa-" + UUID.randomUUID(), PlatformPermissions.RECORDING_KEY_MANAGE);
		KeyPairGenerator rsa = KeyPairGenerator.getInstance("RSA");
		rsa.initialize(2048);
		String key = Base64.getEncoder().encodeToString(rsa.generateKeyPair().getPublic().getEncoded());

		client.put().uri("/v1/operator-settings/recording-customer-key").header("Authorization", "Bearer " + bearer)
				.contentType(MediaType.APPLICATION_JSON).bodyValue(keyBody(key, "ecies_p256")).exchange().expectStatus()
				.isEqualTo(422);
	}

	/**
	 * The seal algorithm itself, not the key. {@code rsa_oaep_sha256} is in the
	 * contract enum and the DB CHECK because both are widened and never narrowed,
	 * but the Gateway seals with ECIES on P-256 only, so storing a key under it
	 * would fail-close every session at the first recording.
	 *
	 * <p>
	 * The refusal rests on a single {@code else} branch, and
	 * {@code CustomerPublicKeys.isValid(rsa2048, "rsa_oaep_sha256")} returns
	 * {@code true} — so nothing beneath this assertion would object if that branch
	 * were removed. A valid RSA key is used deliberately: a malformed one would
	 * pass this test against a guard that had stopped checking the algorithm at
	 * all.
	 */
	@Test
	void anAlgorithmTheDataPlaneDoesNotImplementIsRefusedEvenWithAMatchingKey() throws Exception {
		String bearer = tokenWith("svc-rk-alg-" + UUID.randomUUID(), PlatformPermissions.RECORDING_KEY_MANAGE);
		KeyPairGenerator rsa = KeyPairGenerator.getInstance("RSA");
		rsa.initialize(2048);
		String key = Base64.getEncoder().encodeToString(rsa.generateKeyPair().getPublic().getEncoded());

		client.put().uri("/v1/operator-settings/recording-customer-key").header("Authorization", "Bearer " + bearer)
				.contentType(MediaType.APPLICATION_JSON).bodyValue(keyBody(key, "rsa_oaep_sha256")).exchange()
				.expectStatus().isEqualTo(422).expectBody().jsonPath("$.detail")
				.value(org.hamcrest.Matchers.containsString("not implemented by the data plane"));

		assertThat(settings.findSingleton().block().recordingCustomerPublicKey()).isNull();
	}

	@Test
	void aP384KeySubmittedAsEciesP256IsRefused() throws Exception {
		String bearer = tokenWith("svc-rk-p384-" + UUID.randomUUID(), PlatformPermissions.RECORDING_KEY_MANAGE);

		client.put().uri("/v1/operator-settings/recording-customer-key").header("Authorization", "Bearer " + bearer)
				.contentType(MediaType.APPLICATION_JSON).bodyValue(keyBody(spki(ec("secp384r1")), "ecies_p256"))
				.exchange().expectStatus().isEqualTo(422);
	}

	@Test
	void garbageBytesAreRefused() {
		String bearer = tokenWith("svc-rk-garbage-" + UUID.randomUUID(), PlatformPermissions.RECORDING_KEY_MANAGE);

		client.put().uri("/v1/operator-settings/recording-customer-key").header("Authorization", "Bearer " + bearer)
				.contentType(MediaType.APPLICATION_JSON)
				.bodyValue(keyBody(Base64.getEncoder().encodeToString(new byte[]{1, 2, 3, 4}), "ecies_p256")).exchange()
				.expectStatus().isEqualTo(422);
	}

	@Test
	void aKeyRefCarryingKeyMaterialIsRefused() throws Exception {
		String bearer = tokenWith("svc-rk-ref-" + UUID.randomUUID(), PlatformPermissions.RECORDING_KEY_MANAGE);
		Map<String, Object> body = keyBody(spki(ec("secp256r1")), "ecies_p256");
		body.put("keyRef", "-----BEGIN PRIVATE KEY-----");

		client.put().uri("/v1/operator-settings/recording-customer-key").header("Authorization", "Bearer " + bearer)
				.contentType(MediaType.APPLICATION_JSON).bodyValue(body).exchange().expectStatus().isEqualTo(422);
	}

	@Test
	void rotationFieldsOnAFirstProvisioningAreRefused() throws Exception {
		String bearer = tokenWith("svc-rk-early-" + UUID.randomUUID(), PlatformPermissions.RECORDING_KEY_MANAGE);
		Map<String, Object> body = keyBody(spki(ec("secp256r1")), "ecies_p256");
		body.put("acknowledgeExistingRecordingsUndecryptable", true);

		client.put().uri("/v1/operator-settings/recording-customer-key").header("Authorization", "Bearer " + bearer)
				.contentType(MediaType.APPLICATION_JSON).bodyValue(body).exchange().expectStatus().isEqualTo(422);
	}

	@Test
	void rotationRequiresTheAcknowledgementAndTheOutgoingFingerprint() throws Exception {
		String admin = "svc-rk-rotate-" + UUID.randomUUID();
		String bearer = tokenWith(admin, PlatformPermissions.RECORDING_KEY_MANAGE);
		KeyPair outgoing = ec("secp256r1");
		KeyPair incoming = ec("secp256r1");
		provision(bearer, outgoing);

		Map<String, Object> noAck = keyBody(spki(incoming), "ecies_p256");
		noAck.put("expectedFingerprintSha256", fingerprint(outgoing));
		client.put().uri("/v1/operator-settings/recording-customer-key").header("Authorization", "Bearer " + bearer)
				.contentType(MediaType.APPLICATION_JSON).bodyValue(noAck).exchange().expectStatus().isEqualTo(422);

		Map<String, Object> noEcho = keyBody(spki(incoming), "ecies_p256");
		noEcho.put("acknowledgeExistingRecordingsUndecryptable", true);
		client.put().uri("/v1/operator-settings/recording-customer-key").header("Authorization", "Bearer " + bearer)
				.contentType(MediaType.APPLICATION_JSON).bodyValue(noEcho).exchange().expectStatus().isEqualTo(422);

		Map<String, Object> wrongEcho = keyBody(spki(incoming), "ecies_p256");
		wrongEcho.put("expectedFingerprintSha256", fingerprint(incoming));
		wrongEcho.put("acknowledgeExistingRecordingsUndecryptable", true);
		client.put().uri("/v1/operator-settings/recording-customer-key").header("Authorization", "Bearer " + bearer)
				.contentType(MediaType.APPLICATION_JSON).bodyValue(wrongEcho).exchange().expectStatus().isEqualTo(409);

		assertThat(settings.findSingleton().block().recordingCustomerPublicKey())
				.isEqualTo(outgoing.getPublic().getEncoded());

		Map<String, Object> good = keyBody(spki(incoming), "ecies_p256");
		good.put("expectedFingerprintSha256", fingerprint(outgoing));
		good.put("acknowledgeExistingRecordingsUndecryptable", true);
		client.put().uri("/v1/operator-settings/recording-customer-key").header("Authorization", "Bearer " + bearer)
				.contentType(MediaType.APPLICATION_JSON).bodyValue(good).exchange().expectStatus().isOk().expectBody()
				.jsonPath("$.fingerprintSha256").isEqualTo(fingerprint(incoming));

		List<AuditEvent> audit = auditEvents.findByActor(admin).collectList().block();
		assertThat(audit).anySatisfy(e -> {
			assertThat(e.action()).isEqualTo("operator_settings.recording_key.rotate");
			assertThat(e.detail().get("before").get("fingerprintSha256").stringValue())
					.isEqualTo(fingerprint(outgoing));
			assertThat(e.detail().get("after").get("fingerprintSha256").stringValue()).isEqualTo(fingerprint(incoming));
			assertThat(e.detail().toString()).doesNotContain(spki(outgoing)).doesNotContain(spki(incoming));
		});
	}

	/**
	 * {@code keyRef} points at where the customer's recording PRIVATE key is held,
	 * which is the same shape of value {@code kek_reference} is excluded outright
	 * to avoid disclosing — and this one names a key held outside the platform,
	 * where our controls do not reach. So it is projected only to the permission
	 * that manages the key. Everything an operator needs to confirm a provisioning
	 * stays at {@code rbac:read}.
	 */
	@Test
	void theKeyReferenceIsHiddenFromAReaderWhoCannotManageTheKey() throws Exception {
		String bearer = tokenWith("svc-rk-ref-" + UUID.randomUUID(), PlatformPermissions.RECORDING_KEY_MANAGE,
				PlatformPermissions.RBAC_READ);
		KeyPair pair = ec("secp256r1");
		Map<String, Object> body = keyBody(spki(pair), "ecies_p256");
		body.put("keyRef", "vault://customer/recording-key");
		client.put().uri("/v1/operator-settings/recording-customer-key").header("Authorization", "Bearer " + bearer)
				.contentType(MediaType.APPLICATION_JSON).bodyValue(body).exchange().expectStatus().isOk();

		String readerOnly = tokenWith("svc-rk-ro-" + UUID.randomUUID(), PlatformPermissions.RBAC_READ);
		for (String uri : new String[]{"/v1/operator-settings", "/v1/operator-settings/recording-customer-key"}) {
			client.get().uri(uri).header("Authorization", "Bearer " + readerOnly).exchange().expectStatus().isOk()
					.expectBody().jsonPath("$.recordingKeyRef").doesNotExist().jsonPath("$.keyRef").doesNotExist();
		}

		// The other half of the assertion: the field IS set, so its absence above is
		// the permission gate and not an unprovisioned reference. Without this a
		// projection that dropped keyRef for everyone would pass.
		client.get().uri("/v1/operator-settings/recording-customer-key").header("Authorization", "Bearer " + bearer)
				.exchange().expectStatus().isOk().expectBody().jsonPath("$.keyRef")
				.isEqualTo("vault://customer/recording-key").jsonPath("$.fingerprintSha256")
				.isEqualTo(fingerprint(pair));

		client.get().uri("/v1/operator-settings/recording-customer-key").header("Authorization", "Bearer " + readerOnly)
				.exchange().expectStatus().isOk().expectBody().jsonPath("$.configured").isEqualTo(true)
				.jsonPath("$.fingerprintSha256").isEqualTo(fingerprint(pair)).jsonPath("$.publicKey")
				.isEqualTo(spki(pair));
	}

	@Test
	void settingsWriteAloneCannotWriteTheRecordingKey() throws Exception {
		String settingsAdmin = tokenWith("svc-rk-sw-" + UUID.randomUUID(), PlatformPermissions.SETTINGS_WRITE,
				PlatformPermissions.RBAC_READ);

		client.put().uri("/v1/operator-settings/recording-customer-key")
				.header("Authorization", "Bearer " + settingsAdmin).contentType(MediaType.APPLICATION_JSON)
				.bodyValue(keyBody(spki(ec("secp256r1")), "ecies_p256")).exchange().expectStatus().isForbidden();

		assertThat(settings.findSingleton().block().recordingCustomerPublicKey()).isNull();
	}

	// Un-provisioning would fail-close every future session, so the API offers no
	// way to do it. What matters is that the key survives the attempt.
	@Test
	void thereIsNoDeleteForTheRecordingKey() throws Exception {
		String bearer = tokenWith("svc-rk-del-" + UUID.randomUUID(), PlatformPermissions.RECORDING_KEY_MANAGE);
		KeyPair pair = ec("secp256r1");
		provision(bearer, pair);

		client.delete().uri("/v1/operator-settings/recording-customer-key").header("Authorization", "Bearer " + bearer)
				.exchange().expectStatus().is4xxClientError();

		assertThat(settings.findSingleton().block().recordingCustomerPublicKey())
				.isEqualTo(pair.getPublic().getEncoded());
	}

	private void provision(String bearer, KeyPair pair) {
		client.put().uri("/v1/operator-settings/recording-customer-key").header("Authorization", "Bearer " + bearer)
				.contentType(MediaType.APPLICATION_JSON).bodyValue(keyBody(spki(pair), "ecies_p256")).exchange()
				.expectStatus().isOk();
	}
}
