package io.sessionlayer.controlplane.ca;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.catchThrowable;

import io.sessionlayer.controlplane.ca.backend.aws.AwsKmsSigner.KmsSigningException;
import io.sessionlayer.controlplane.ca.backend.aws.LocalStackKms;
import io.sessionlayer.controlplane.ca.cert.CertificateProfiles;
import io.sessionlayer.controlplane.ca.key.SshEcdsaPublicKeys;
import io.sessionlayer.controlplane.configapi.CaConfigService;
import io.sessionlayer.controlplane.data.config.CaConfig;
import io.sessionlayer.controlplane.data.config.CaConfigRepository;
import io.sessionlayer.controlplane.data.runtime.CaKeyMaterial;
import io.sessionlayer.controlplane.data.runtime.CaKeyMaterialRepository;
import io.sessionlayer.controlplane.support.AbstractAuthIT;
import io.sessionlayer.controlplane.web.ApiProblemException;
import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.Duration;
import java.time.Instant;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

class AwsKmsRotationIT extends AbstractAuthIT {

	private static final String ACTOR = "svc-awskms-it";

	@DynamicPropertySource
	static void kms(DynamicPropertyRegistry registry) {
		registry.add("sessionlayer.ca.aws.enabled", () -> "true");
		registry.add("sessionlayer.ca.aws.region", LocalStackKms::region);
		registry.add("sessionlayer.ca.aws.account-id", () -> LocalStackKms.ACCOUNT_ID);
		registry.add("sessionlayer.ca.aws.endpoint-override", () -> LocalStackKms.endpoint().toString());
		registry.add("sessionlayer.ca.aws.allow-endpoint-override", () -> "true");
		registry.add("sessionlayer.ca.aws.allow-insecure-endpoint", () -> "true");
	}

	@Autowired
	private CaConfigService caConfigService;
	@Autowired
	private CaSignerService signerService;
	@Autowired
	private CaConfigRepository caConfigs;
	@Autowired
	private CaKeyMaterialRepository caKeyMaterials;

	@AfterEach
	void resetCas() {
		// ca_key_material rows cascade with their ca_config row.
		caConfigs.deleteAll().block();
	}

	private UUID seedActiveLocalCa() {
		return caConfigService.create(ACTOR, "ca-" + UUID.randomUUID(), "session", "local",
				"local:seed-" + UUID.randomUUID(), "ecdsa-p256").block().id();
	}

	private static ECPublicKey kmsPublicKey(String keyArn) throws Exception {
		byte[] spki = LocalStackKms.admin().getPublicKey(request -> request.keyId(keyArn)).publicKey().asByteArray();
		return (ECPublicKey) KeyFactory.getInstance("EC").generatePublic(new X509EncodedKeySpec(spki));
	}

	private static ECPublicKey subjectKey() throws Exception {
		KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
		generator.initialize(new ECGenParameterSpec("secp256r1"));
		return (ECPublicKey) generator.generateKeyPair().getPublic();
	}

	@Test
	void rotatingOntoAwsKmsAdoptsTheRealKeyAndStoresNoPrivateMaterial() throws Exception {
		String keyArn = LocalStackKms.createSigningKey();
		UUID seeded = seedActiveLocalCa();

		CaConfig active = caConfigService.rotate(seeded, ACTOR, "aws_kms", keyArn, "ecdsa-p256").block();

		assertThat(active.backend()).isEqualTo("aws_kms");
		assertThat(active.keyReference()).isEqualTo(keyArn);
		assertThat(active.rotationState()).isEqualTo("active");
		assertThat(active.id()).isNotEqualTo(seeded);

		CaKeyMaterial material = caKeyMaterials.findByCaConfigId(active.id()).block();
		assertThat(material.keyLocation()).isEqualTo(CaKeyMaterial.EXTERNAL);
		assertThat(material.wrappedKey()).isNull();
		assertThat(material.iv()).isNull();
		assertThat(material.kekReference()).isNull();
		assertThat(material.publicKey()).isEqualTo(kmsPublicKey(keyArn).getEncoded());
	}

	@Test
	void theRotatedCaIssuesCertificatesSignedByTheKmsHeldKey() throws Exception {
		String keyArn = LocalStackKms.createSigningKey();
		caConfigService.rotate(seedActiveLocalCa(), ACTOR, "aws_kms", keyArn, "ecdsa-p256").block();

		SshCertSigner signer = signerService.activeSigner("session").block(Duration.ofSeconds(10));
		OpenSshCertificate certificate = signer.signCertificate(
				new CertificateRequest(subjectKey(), CertificateProfiles.innerLegSessionCert("sess-kms", "alice@corp",
						"deploy", "10.0.0.0/8", Set.of("shell"), 7L, Instant.now())));

		ECPublicKey caPublicKey = SshEcdsaPublicKeys.parse(signer.caPublicKeyBlob());
		assertThat(caPublicKey.getEncoded()).isEqualTo(kmsPublicKey(keyArn).getEncoded());
		assertThat(CertTestSupport.verifyEcdsaCert(certificate.blob(), caPublicKey)).isTrue();
	}

	/**
	 * The signer is still built — construction is I/O-free by design — and it is
	 * still the KMS one, so a key that stops signing surfaces as a refused
	 * certificate rather than as a certificate no node trusts.
	 */
	@Test
	void aKmsKeyThatStopsSigningNeverDegradesToTheLocalBackend() throws Exception {
		String keyArn = LocalStackKms.createSigningKey();
		caConfigService.rotate(seedActiveLocalCa(), ACTOR, "aws_kms", keyArn, "ecdsa-p256").block();
		LocalStackKms.disable(keyArn);

		SshCertSigner signer = signerService.activeSigner("session").block(Duration.ofSeconds(10));

		assertThat(SshEcdsaPublicKeys.parse(signer.caPublicKeyBlob()).getEncoded())
				.isEqualTo(kmsPublicKey(keyArn).getEncoded());
		Throwable thrown = catchThrowable(() -> signer.signCertificate(
				new CertificateRequest(subjectKey(), CertificateProfiles.innerLegSessionCert("sess-kms-down",
						"alice@corp", "deploy", "10.0.0.0/8", Set.of("shell"), 8L, Instant.now()))));
		assertThat(thrown).isInstanceOf(KmsSigningException.class);
		assertThat(caConfigs.findByCaKindAndRotationState("session", "active").block().backend()).isEqualTo("aws_kms");
	}

	@Test
	void anAliasReferenceIsRefusedAtRotationAndWritesNothing() {
		String alias = LocalStackKms.createAlias(LocalStackKms.createSigningKey());
		UUID seeded = seedActiveLocalCa();
		long before = caConfigs.count().block();

		assertThatThrownBy(() -> caConfigService.rotate(seeded, ACTOR, "aws_kms", alias, "ecdsa-p256").block())
				.isInstanceOf(ApiProblemException.class).hasMessageContaining("is a KMS alias");

		assertThat(caConfigs.count().block()).isEqualTo(before);
		CaConfig stillActive = caConfigs.findByCaKindAndRotationState("session", "active").block();
		assertThat(stillActive.id()).isEqualTo(seeded);
		assertThat(stillActive.backend()).isEqualTo("local");
	}

	@Test
	void anArnInAnotherAccountIsRefusedAtRotationAndWritesNothing() {
		String foreign = "arn:aws:kms:" + LocalStackKms.region()
				+ ":111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab";
		UUID seeded = seedActiveLocalCa();
		long before = caConfigs.count().block();

		assertThatThrownBy(() -> caConfigService.rotate(seeded, ACTOR, "aws_kms", foreign, "ecdsa-p256").block())
				.isInstanceOf(ApiProblemException.class)
				.hasMessageContaining("only the configured account, region and partition are permitted");

		assertThat(caConfigs.count().block()).isEqualTo(before);
		assertThat(caConfigs.findByCaKindAndRotationState("session", "active").block().backend()).isEqualTo("local");
	}
}
