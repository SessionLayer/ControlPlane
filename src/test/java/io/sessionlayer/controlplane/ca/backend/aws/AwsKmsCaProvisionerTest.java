package io.sessionlayer.controlplane.ca.backend.aws;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import io.sessionlayer.controlplane.ca.CaBackendCapabilities;
import io.sessionlayer.controlplane.ca.CaKeyProvisioner;
import io.sessionlayer.controlplane.ca.CaKeyProvisioner.Request;
import io.sessionlayer.controlplane.ca.backend.aws.KmsKeyArn.InvalidKeyReference;
import io.sessionlayer.controlplane.data.config.CaConfig;
import io.sessionlayer.controlplane.data.runtime.CaKeyMaterial;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import org.junit.jupiter.api.Test;

/**
 * {@link AwsKmsCaProvisioner} is the rotation-time bridge between
 * {@link KmsKeyArn} (write-path pinning/allow-list) and
 * {@link AwsKmsSignerFactory#fetchPublicKey} (the one KMS read). This class
 * proves the wiring — parse, validate, fetch, build — with the factory mocked,
 * matching how {@code CaSignerServiceTest} proves the sign-time half.
 */
class AwsKmsCaProvisionerTest {

	private static final KmsKeyArn.Anchor ANCHOR = new KmsKeyArn.Anchor("aws", "us-east-1", "111122223333");

	private static final String KEY_ARN = "arn:aws:kms:us-east-1:111122223333:key/"
			+ "1234abcd-12ab-34cd-56ef-1234567890ab";

	private static ECPublicKey ecPublicKey() {
		try {
			KeyPairGenerator g = KeyPairGenerator.getInstance("EC");
			g.initialize(new ECGenParameterSpec("secp256r1"));
			KeyPair pair = g.generateKeyPair();
			return (ECPublicKey) pair.getPublic();
		} catch (Exception e) {
			throw new IllegalStateException(e);
		}
	}

	private static AwsKmsSignerFactory factoryReturning(ECPublicKey publicKey) {
		AwsKmsSignerFactory factory = mock(AwsKmsSignerFactory.class);
		when(factory.anchor()).thenReturn(ANCHOR);
		when(factory.fetchPublicKey(any())).thenReturn(publicKey);
		return factory;
	}

	@Test
	void backendIsAwsKms() {
		assertThat(new AwsKmsCaProvisioner(mock(AwsKmsSignerFactory.class)).backend()).isEqualTo("aws_kms");
	}

	@Test
	void provisionsFromAKeyArnInTheConfiguredAccount() {
		ECPublicKey publicKey = ecPublicKey();
		AwsKmsCaProvisioner provisioner = new AwsKmsCaProvisioner(factoryReturning(publicKey));

		CaKeyProvisioner.Provisioned result = provisioner
				.provision(new Request("session", "session-ca", "incoming", KEY_ARN, "ecdsa-p256"));

		CaConfig config = result.config();
		assertThat(config.backend()).isEqualTo("aws_kms");
		assertThat(config.caKind()).isEqualTo("session");
		assertThat(config.rotationState()).isEqualTo("incoming");
		assertThat(config.algorithm()).isEqualTo("ecdsa-p256");
		assertThat(config.keyReference()).isEqualTo(KEY_ARN);

		CaKeyMaterial material = result.material();
		assertThat(material.caConfigId()).isEqualTo(config.id());
		assertThat(material.keyLocation()).isEqualTo(CaKeyMaterial.EXTERNAL);
		// No private half is persisted, in any column, ever — that is the whole
		// point of adopting a key held in a key service.
		assertThat(material.wrappedKey()).isNull();
		assertThat(material.iv()).isNull();
		assertThat(material.kekReference()).isNull();
		assertThat(material.publicKey()).isEqualTo(publicKey.getEncoded());
		assertThat(material.keyType()).isEqualTo("ecdsa-sha2-nistp256");
	}

	@Test
	void refusesAnAliasBeforeEverCallingKms() {
		AwsKmsSignerFactory factory = factoryReturning(ecPublicKey());
		AwsKmsCaProvisioner provisioner = new AwsKmsCaProvisioner(factory);

		assertThatThrownBy(() -> provisioner.provision(new Request("session", "session-ca", "incoming",
				"arn:aws:kms:us-east-1:111122223333:alias/session-ca", "ecdsa-p256")))
				.isInstanceOf(InvalidKeyReference.class);

		// anchor() is called to build the allow-list argument itself; fetchPublicKey
		// is the actual KMS call, and it must never happen.
		verify(factory, never()).fetchPublicKey(any());
	}

	@Test
	void refusesAKeyArnInAnotherAccountBeforeEverCallingKms() {
		AwsKmsSignerFactory factory = factoryReturning(ecPublicKey());
		AwsKmsCaProvisioner provisioner = new AwsKmsCaProvisioner(factory);

		assertThatThrownBy(() -> provisioner.provision(new Request("session", "session-ca", "incoming",
				"arn:aws:kms:us-east-1:999988887777:key/1234abcd-12ab-34cd-56ef-1234567890ab", "ecdsa-p256")))
				.isInstanceOf(InvalidKeyReference.class);

		verify(factory, never()).fetchPublicKey(any());
	}

	@Test
	void refusesAnUnsupportedAlgorithmWithoutParsingTheReferenceOrCallingKms() {
		AwsKmsSignerFactory factory = factoryReturning(ecPublicKey());
		AwsKmsCaProvisioner provisioner = new AwsKmsCaProvisioner(factory);

		assertThatThrownBy(() -> provisioner
				.provision(new Request("session", "session-ca", "incoming", KEY_ARN, "ed25519")))
				.isInstanceOf(CaBackendCapabilities.AlgorithmNotSupported.class);

		verifyNoInteractions(factory);
	}

	/**
	 * A KMS read that fails — an unreachable endpoint, a rejected credential, a
	 * disabled key — aborts the rotation having written nothing, rather than
	 * falling through to a key this Control Plane could generate itself.
	 */
	@Test
	void aFailedKmsReadAbortsTheAdoptionRatherThanProvisioningAnything() {
		AwsKmsSignerFactory factory = mock(AwsKmsSignerFactory.class);
		when(factory.anchor()).thenReturn(ANCHOR);
		when(factory.fetchPublicKey(any())).thenThrow(new IllegalStateException("KMS key is disabled"));

		assertThatThrownBy(() -> new AwsKmsCaProvisioner(factory)
				.provision(new Request("session", "session-ca", "incoming", KEY_ARN, "ecdsa-p256")))
				.isInstanceOf(IllegalStateException.class);
	}
}
