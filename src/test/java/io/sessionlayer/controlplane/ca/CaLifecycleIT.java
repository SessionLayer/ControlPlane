package io.sessionlayer.controlplane.ca;

import static org.assertj.core.api.Assertions.assertThat;

import io.sessionlayer.controlplane.ca.cert.CertificateProfiles;
import io.sessionlayer.controlplane.ca.key.SshEcdsaPublicKeys;
import io.sessionlayer.controlplane.configapi.CaConfigService;
import io.sessionlayer.controlplane.data.config.CaConfig;
import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.postgresql.PostgreSQLContainer;
import reactor.test.StepVerifier;

@Testcontainers
@SpringBootTest(properties = {"spring.grpc.server.port=0", "sessionlayer.coldstart.enabled=false"})
class CaLifecycleIT {

	@Container
	static final PostgreSQLContainer POSTGRES = new PostgreSQLContainer("postgres:17-alpine")
			.withDatabaseName("sessionlayer").withUsername("sessionlayer").withPassword("sessionlayer");

	@DynamicPropertySource
	static void props(DynamicPropertyRegistry registry) {
		registry.add("spring.r2dbc.url", () -> String.format("r2dbc:postgresql://%s:%d/%s", POSTGRES.getHost(),
				POSTGRES.getMappedPort(PostgreSQLContainer.POSTGRESQL_PORT), POSTGRES.getDatabaseName()));
		registry.add("spring.r2dbc.username", () -> "cp_runtime");
		registry.add("spring.r2dbc.password", () -> "cp_runtime");
		registry.add("spring.flyway.url", POSTGRES::getJdbcUrl);
		registry.add("spring.flyway.user", POSTGRES::getUsername);
		registry.add("spring.flyway.password", POSTGRES::getPassword);
		registry.add("spring.flyway.placeholders.cpRuntimePassword", () -> "cp_runtime");
		registry.add("sessionlayer.ca.local.allow-dev-kek", () -> "true");
	}

	@Autowired
	private CaProvisioningService provisioning;
	@Autowired
	private CaSignerService signerService;
	@Autowired
	private CaRotationService rotationService;
	@Autowired
	private CaConfigService caConfigService;
	@Autowired
	private io.sessionlayer.controlplane.data.config.CaConfigRepository caConfigs;
	@Autowired
	private io.sessionlayer.controlplane.data.runtime.CaKeyMaterialRepository caKeyMaterials;

	private static ECPublicKey subjectKey() throws Exception {
		KeyPairGenerator g = KeyPairGenerator.getInstance("EC");
		g.initialize(new ECGenParameterSpec("secp256r1"));
		return (ECPublicKey) g.generateKeyPair().getPublic();
	}

	@Test
	void activeSignerFailsClosedWithNoCa() {
		// Clean slate (this class's own container): no active session CA -> fail
		// closed.
		// ca_key_material is INSERT/SELECT-only for the runtime role, so clean up as
		// owner.
		OwnerDb.of(POSTGRES).sql("DELETE FROM runtime.ca_key_material").then()
				.then(OwnerDb.of(POSTGRES).sql("DELETE FROM config.ca_config").then()).block(Duration.ofSeconds(10));
		StepVerifier.create(signerService.activeSigner("session")).verifyError(CaSignerService.NoSignerAvailable.class);
	}

	@Test
	void provisionedSignerProducesAVerifiableCert() throws Exception {
		provisioning.provisionAll().block(Duration.ofSeconds(20));
		SshCertSigner signer = signerService.activeSigner("session").block(Duration.ofSeconds(10));
		assertThat(signer).isNotNull();
		assertThat(signer.capabilities().supports("ecdsa-p256")).isTrue();

		var params = CertificateProfiles.innerLegSessionCert("sess-life", "alice@corp", "deploy", "10.0.0.0/8",
				Set.of("shell", "exec"), 5L, Instant.now());
		OpenSshCertificate cert = signer.signCertificate(new CertificateRequest(subjectKey(), params));

		ECPublicKey caPublicKey = SshEcdsaPublicKeys.parse(signer.caPublicKeyBlob());
		assertThat(CertTestSupport.verifyEcdsaCert(cert.blob(), caPublicKey)).isTrue();
		// the CA advertises a TrustedUserCAKeys line for the node fleet.
		assertThat(signer.caAuthorizedKey("session-ca")).startsWith("ecdsa-sha2-nistp256 ");
	}

	@Test
	void rotationOverlapThenDrainKeepsTrustContinuous() {
		provisioning.provisionAll().block(Duration.ofSeconds(20));
		// Steady state: one active session CA is trusted.
		assertThat(trusted()).hasSize(1);

		// Begin rotation: an incoming CA is pre-published -> both trusted (overlap
		// starts).
		rotationService.beginRotation("session", "session-ca-2", "local", null, "ecdsa-p256")
				.block(Duration.ofSeconds(10));
		assertThat(trusted()).hasSize(2);

		// Promote: old active -> outgoing, incoming -> active. Still both trusted (no
		// downtime).
		rotationService.promote("session").block(Duration.ofSeconds(10));
		assertThat(trusted()).hasSize(2);
		assertThat(activeName()).isEqualTo("session-ca-2"); // the new CA is now the signer

		// Drain: outgoing -> expired -> only the new CA remains trusted.
		rotationService.drain("session").block(Duration.ofSeconds(10));
		assertThat(trusted()).hasSize(1);
	}

	/**
	 * A rotation that names a stronger curve must produce that curve, not silently
	 * keep the default P-256 the local factory used to hard-code — and a later
	 * rotation that omits the algorithm must inherit the CA's now-current curve,
	 * not reset to it either. Both are checked against the actual generated key
	 * (its EC field size), not just the {@code ca_config.algorithm} label, so a fix
	 * that only relabels the row without generating a real stronger key would still
	 * fail here.
	 *
	 * <p>
	 * Exercised on {@code host}, not {@code session}: two rotations with no drain
	 * between them leave more than one CA trusted, and other tests in this class
	 * assert an exact trusted-set size for {@code session}.
	 */
	@Test
	void rotationHonorsAnExplicitAlgorithmThenInheritsItRatherThanSilentlyDowngrading() throws Exception {
		provisioning.provisionAll().block(Duration.ofSeconds(20));
		UUID activeId = activeCaId("host");

		CaConfig p384 = caConfigService.rotate(activeId, "it-actor", null, null, "ecdsa-p384")
				.block(Duration.ofSeconds(10));
		assertThat(p384.algorithm()).isEqualTo("ecdsa-p384");
		assertThat(curveFieldSizeBits(publicKeyOf(p384))).isEqualTo(384);

		CaConfig again = caConfigService.rotate(p384.id(), "it-actor", null, null, null).block(Duration.ofSeconds(10));
		assertThat(again.algorithm()).isEqualTo("ecdsa-p384");
		assertThat(curveFieldSizeBits(publicKeyOf(again))).isEqualTo(384);
	}

	@Test
	void backendAlgorithmMismatchRejectedAtValidation() {
		// ed25519 is not producible by our ECDSA assembler -> rejected at validation.
		CaConfig ed = new CaConfig(io.sessionlayer.controlplane.data.Uuids.v7(), "bad-ed25519", "user", "local",
				"local:x", "ed25519", "active", "default", null, null, null);
		StepVerifier.create(signerService.signerFor(ed)).verifyError(CaBackendCapabilities.AlgorithmNotSupported.class);
	}

	@Autowired
	private org.springframework.r2dbc.core.DatabaseClient db;

	private List<String> trusted() {
		return rotationService.trustedCaKeys("session").block(Duration.ofSeconds(10));
	}

	private String activeName() {
		return db.sql("SELECT name FROM config.ca_config WHERE ca_kind = 'session' AND rotation_state = 'active'")
				.map(row -> row.get(0, String.class)).one().block();
	}

	private UUID activeCaId(String kind) {
		return caConfigs.findByCaKindAndRotationState(kind, "active").map(CaConfig::id).block(Duration.ofSeconds(10));
	}

	private byte[] publicKeyOf(CaConfig config) {
		return caKeyMaterials.findByCaConfigId(config.id())
				.map(io.sessionlayer.controlplane.data.runtime.CaKeyMaterial::publicKey).block(Duration.ofSeconds(10));
	}

	private static int curveFieldSizeBits(byte[] x509PublicKey) throws Exception {
		var publicKey = (ECPublicKey) KeyFactory.getInstance("EC")
				.generatePublic(new X509EncodedKeySpec(x509PublicKey));
		return publicKey.getParams().getCurve().getField().getFieldSize();
	}
}
