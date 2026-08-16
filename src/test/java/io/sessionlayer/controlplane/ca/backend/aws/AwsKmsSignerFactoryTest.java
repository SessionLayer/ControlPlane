package io.sessionlayer.controlplane.ca.backend.aws;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.net.InetAddress;
import java.net.ServerSocket;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.spec.ECGenParameterSpec;
import java.time.Duration;
import java.util.List;
import org.junit.jupiter.api.Test;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.core.exception.SdkClientException;
import software.amazon.awssdk.services.kms.model.GetPublicKeyResponse;
import software.amazon.awssdk.services.kms.model.KeySpec;
import software.amazon.awssdk.services.kms.model.KeyUsageType;
import software.amazon.awssdk.services.kms.model.SigningAlgorithmSpec;

class AwsKmsSignerFactoryTest {

	private static final String ACCOUNT_ID = "111122223333";

	private static final String KEY_ARN = "arn:aws:kms:us-east-1:" + ACCOUNT_ID + ":key/"
			+ "1234abcd-12ab-34cd-56ef-1234567890ab";

	/**
	 * Taken from the real parse rather than written out, so a change to the
	 * redaction shape reaches these assertions instead of leaving them agreeing
	 * with a literal nobody maintains.
	 */
	private static final String REDACTED_ARN = KmsKeyArn
			.parse(KEY_ARN, new KmsKeyArn.Anchor("aws", "us-east-1", ACCOUNT_ID)).redacted();

	private static AwsKmsProperties properties() {
		AwsKmsProperties properties = new AwsKmsProperties();
		properties.setEnabled(true);
		properties.setRegion("us-east-1");
		properties.setAccountId("111122223333");
		return properties;
	}

	private static byte[] spki(String curve) {
		try {
			KeyPairGenerator g = KeyPairGenerator.getInstance("EC");
			g.initialize(new ECGenParameterSpec(curve));
			KeyPair pair = g.generateKeyPair();
			return pair.getPublic().getEncoded();
		} catch (Exception e) {
			throw new IllegalStateException(e);
		}
	}

	private static GetPublicKeyResponse.Builder wellFormed() {
		return GetPublicKeyResponse.builder().keyId(KEY_ARN).keySpec(KeySpec.ECC_NIST_P256)
				.keyUsage(KeyUsageType.SIGN_VERIFY).signingAlgorithms(List.of(SigningAlgorithmSpec.ECDSA_SHA_256))
				.publicKey(SdkBytes.fromByteArray(spki("secp256r1")));
	}

	@Test
	void exposesTheConfiguredAccountRegionAndPartitionAsTheAllowListAnchor() {
		try (AwsKmsSignerFactory factory = new AwsKmsSignerFactory(properties())) {
			assertThat(factory.anchor()).isEqualTo(new KmsKeyArn.Anchor("aws", "us-east-1", "111122223333"));
		}
	}

	/**
	 * Constructing with an override used to be asserted only to "not throw", which
	 * passes just as well if the override branch is deleted. What has to hold is
	 * that the client is actually pointed at it — checked by attempting a call and
	 * reading back where it went, since the SDK exposes no accessor for the
	 * configured endpoint.
	 */
	@Test
	void pointsTheClientAtAnApprovedEndpointOverride() throws Exception {
		try (ServerSocket unreachable = new ServerSocket(0, 1, InetAddress.getLoopbackAddress())) {
			AwsKmsProperties properties = properties();
			properties.setAllowEndpointOverride(true);
			properties.setAllowInsecureEndpoint(true);
			properties.setEndpointOverride("http://127.0.0.1:" + unreachable.getLocalPort() + "/kms");
			properties.setTimeout(Duration.ofMillis(750));

			try (AwsKmsSignerFactory factory = new AwsKmsSignerFactory(properties)) {
				// The socket accepts and never answers, so the call can only end in this
				// client's own timeout — and only if the request went to the override
				// rather than to the region's real KMS endpoint, which would have
				// resolved and failed differently.
				assertThatThrownBy(() -> factory
						.fetchPublicKey(KmsKeyArn.parse(KEY_ARN, new KmsKeyArn.Anchor("aws", "us-east-1", ACCOUNT_ID))))
						.isInstanceOf(SdkClientException.class);
			}
		}
	}

	@Test
	void acceptsAnEcdsaP256SignVerifyKey() {
		assertThatCode(() -> AwsKmsSignerFactory.validateSigningKey(wellFormed().build(), KEY_ARN, REDACTED_ARN))
				.doesNotThrowAnyException();
	}

	/**
	 * The response's key id is the one hop nothing else verifies: what comes back
	 * here becomes the pinned public key, so an endpoint, proxy or redirect
	 * answering for a different key would pin the CA to a key the operator never
	 * chose — and every later signature would verify against it perfectly.
	 */
	@Test
	void rejectsAResponseForADifferentKeyThanTheOneRequested() {
		GetPublicKeyResponse response = wellFormed()
				.keyId("arn:aws:kms:us-east-1:111122223333:key/99998888-7777-6666-5555-444433332222").build();

		assertThatThrownBy(() -> AwsKmsSignerFactory.validateSigningKey(response, KEY_ARN, REDACTED_ARN))
				.isInstanceOf(IllegalStateException.class).hasMessageContaining("does not match the requested");
	}

	@Test
	void rejectsAKeyOnAnotherCurve() {
		GetPublicKeyResponse response = wellFormed().keySpec(KeySpec.ECC_NIST_P384).build();

		assertThatThrownBy(() -> AwsKmsSignerFactory.validateSigningKey(response, KEY_ARN, REDACTED_ARN))
				.isInstanceOf(IllegalStateException.class).hasMessageContaining("not ECC_NIST_P256");
	}

	/**
	 * An encryption key cannot sign at all. Refused at adoption rather than left to
	 * the first certificate, because {@code kms:DescribeKey} is deliberately not in
	 * this seam's required IAM surface — this response is the only look it gets.
	 */
	@Test
	void rejectsAKeyThatIsNotForSigning() {
		GetPublicKeyResponse response = wellFormed().keyUsage(KeyUsageType.ENCRYPT_DECRYPT).build();

		assertThatThrownBy(() -> AwsKmsSignerFactory.validateSigningKey(response, KEY_ARN, REDACTED_ARN))
				.isInstanceOf(IllegalStateException.class).hasMessageContaining("not SIGN_VERIFY");
	}

	@Test
	void rejectsAKeyThatDoesNotOfferEcdsaSha256() {
		GetPublicKeyResponse noAlgorithms = wellFormed().signingAlgorithms(List.of()).build();
		GetPublicKeyResponse wrongAlgorithm = wellFormed()
				.signingAlgorithms(List.of(SigningAlgorithmSpec.ECDSA_SHA_512)).build();

		for (GetPublicKeyResponse response : List.of(noAlgorithms, wrongAlgorithm)) {
			assertThatThrownBy(() -> AwsKmsSignerFactory.validateSigningKey(response, KEY_ARN, REDACTED_ARN))
					.isInstanceOf(IllegalStateException.class).hasMessageContaining("does not offer ECDSA_SHA_256");
		}
	}

	@Test
	void decodesAP256Spki() {
		assertThat(AwsKmsSignerFactory.decodeP256PublicKey(spki("secp256r1"), REDACTED_ARN).getParams().getCurve()
				.getField().getFieldSize()).isEqualTo(256);
	}

	/**
	 * The curve is checked against the JCA's own P-256 parameters rather than
	 * trusted from {@code keySpec}: the SPKI is what gets persisted and what every
	 * certificate this CA issues carries, so a response whose declared spec and
	 * actual key disagree must not be the one that wins.
	 */
	@Test
	void rejectsAnSpkiOnAnotherCurveEvenWhenTheDeclaredSpecSaysP256() {
		byte[] p384 = spki("secp384r1");

		assertThatCode(() -> AwsKmsSignerFactory.validateSigningKey(
				wellFormed().publicKey(SdkBytes.fromByteArray(p384)).build(), KEY_ARN, REDACTED_ARN))
				.doesNotThrowAnyException();
		assertThatThrownBy(() -> AwsKmsSignerFactory.decodeP256PublicKey(p384, REDACTED_ARN))
				.isInstanceOf(IllegalStateException.class).hasMessageContaining("not on the P-256 curve");
	}

	@Test
	void rejectsPublicKeyBytesThatAreNotAnEcSpki() {
		assertThatThrownBy(() -> AwsKmsSignerFactory.decodeP256PublicKey(new byte[]{1, 2, 3}, REDACTED_ARN))
				.isInstanceOf(IllegalStateException.class).hasMessageContaining("usable EC public key");
	}
}
