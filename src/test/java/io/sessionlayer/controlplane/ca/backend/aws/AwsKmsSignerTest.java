package io.sessionlayer.controlplane.ca.backend.aws;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import io.sessionlayer.controlplane.ca.backend.aws.AwsKmsSigner.KmsSigningException;
import io.sessionlayer.controlplane.ca.sign.EcdsaSignatures;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.util.Arrays;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.Mockito;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.model.KmsInvalidStateException;
import software.amazon.awssdk.services.kms.model.MessageType;
import software.amazon.awssdk.services.kms.model.SignRequest;
import software.amazon.awssdk.services.kms.model.SignResponse;
import software.amazon.awssdk.services.kms.model.SigningAlgorithmSpec;

class AwsKmsSignerTest {

	private static final String ACCOUNT_ID = "111122223333";

	private static final String KEY_ARN = "arn:aws:kms:us-east-1:" + ACCOUNT_ID + ":key/"
			+ "1234abcd-12ab-34cd-56ef-1234567890ab";

	/** Parsed rather than stubbed, so the redaction under test is the real one. */
	private static final KmsKeyArn KEY = KmsKeyArn.parse(KEY_ARN, new KmsKeyArn.Anchor("aws", "us-east-1", ACCOUNT_ID));

	private static KeyPair ecKeyPair() {
		try {
			KeyPairGenerator g = KeyPairGenerator.getInstance("EC");
			g.initialize(new ECGenParameterSpec("secp256r1"));
			return g.generateKeyPair();
		} catch (Exception e) {
			throw new IllegalStateException(e);
		}
	}

	private static byte[] digest32() {
		byte[] d = new byte[32];
		new SecureRandom().nextBytes(d);
		return d;
	}

	/** What KMS returns for {@code ECDSA_SHA_256}: a DER SEQUENCE{r, s}. */
	private static byte[] derSignatureBy(PrivateKey key, byte[] digest) throws Exception {
		Signature s = Signature.getInstance("NONEwithECDSA");
		s.initSign(key);
		s.update(digest);
		return s.sign();
	}

	/** The fixed-width {@code r||s} encoding KMS never returns. */
	private static byte[] p1363SignatureBy(PrivateKey key, byte[] digest) throws Exception {
		EcdsaSignatures.RS rs = EcdsaSignatures.fromDer(derSignatureBy(key, digest));
		byte[] out = new byte[64];
		writeFixed(rs.r(), out, 0);
		writeFixed(rs.s(), out, 32);
		return out;
	}

	private static void writeFixed(BigInteger value, byte[] out, int offset) {
		byte[] raw = value.toByteArray();
		int start = Math.max(0, raw.length - 32);
		int len = raw.length - start;
		System.arraycopy(raw, start, out, offset + (32 - len), len);
	}

	private static SignResponse responseOf(byte[] signature) {
		return SignResponse.builder().keyId(KEY_ARN).signingAlgorithm(SigningAlgorithmSpec.ECDSA_SHA_256)
				.signature(SdkBytes.fromByteArray(signature)).build();
	}

	private static KmsClient clientReturning(SignResponse response) {
		KmsClient kms = mock(KmsClient.class);
		when(kms.sign(any(SignRequest.class))).thenReturn(response);
		return kms;
	}

	@Test
	void signsAndReturnsTheVerifiedDerSignature() throws Exception {
		KeyPair ca = ecKeyPair();
		byte[] digest = digest32();
		byte[] expected = derSignatureBy(ca.getPrivate(), digest);

		AwsKmsSigner signer = new AwsKmsSigner(clientReturning(responseOf(expected)), (ECPublicKey) ca.getPublic(),
				KEY);

		assertThat(signer.signDigestDer(digest)).isEqualTo(expected);
	}

	/**
	 * The request is what makes the digest a digest: with {@code MessageType.RAW}
	 * KMS would hash the 32 bytes again and produce a signature over the wrong
	 * value, and with any other {@code SigningAlgorithm} the curve or hash would
	 * not match the CA key at all.
	 */
	@Test
	void sendsTheDigestAsADigestUnderEcdsaSha256ForThePinnedKey() throws Exception {
		KeyPair ca = ecKeyPair();
		byte[] digest = digest32();
		KmsClient kms = clientReturning(responseOf(derSignatureBy(ca.getPrivate(), digest)));

		new AwsKmsSigner(kms, (ECPublicKey) ca.getPublic(), KEY).signDigestDer(digest);

		ArgumentCaptor<SignRequest> sent = ArgumentCaptor.forClass(SignRequest.class);
		Mockito.verify(kms).sign(sent.capture());
		assertThat(sent.getValue().keyId()).isEqualTo(KEY_ARN);
		assertThat(sent.getValue().signingAlgorithm()).isEqualTo(SigningAlgorithmSpec.ECDSA_SHA_256);
		assertThat(sent.getValue().messageType()).isEqualTo(MessageType.DIGEST);
		assertThat(sent.getValue().message().asByteArray()).isEqualTo(digest);
	}

	@Test
	void rejectsADigestThatIsNotExactly32Bytes() {
		AwsKmsSigner signer = new AwsKmsSigner(mock(KmsClient.class), (ECPublicKey) ecKeyPair().getPublic(), KEY);

		assertThatThrownBy(() -> signer.signDigestDer(new byte[10])).isInstanceOf(KmsSigningException.class)
				.hasMessageContaining("32 bytes");
		assertThatThrownBy(() -> signer.signDigestDer(new byte[33])).isInstanceOf(KmsSigningException.class)
				.hasMessageContaining("32 bytes");
	}

	@Test
	void aSignatureMadeByADifferentKeyFailsTheLocalVerificationGuard() throws Exception {
		KeyPair pinned = ecKeyPair();
		KeyPair impostor = ecKeyPair();
		byte[] digest = digest32();
		byte[] wrongKeySignature = derSignatureBy(impostor.getPrivate(), digest);

		AwsKmsSigner signer = new AwsKmsSigner(clientReturning(responseOf(wrongKeySignature)),
				(ECPublicKey) pinned.getPublic(), KEY);

		assertThatThrownBy(() -> signer.signDigestDer(digest)).isInstanceOf(KmsSigningException.class)
				.hasMessageContaining("does not verify against the pinned public key");
	}

	/**
	 * A P1363 {@code r||s} signature in the DER position must fail — a test that
	 * passes on either encoding proves {@code EcdsaSignatures.fromDer} is not
	 * load-bearing, which is the specific bug it exists to prevent.
	 */
	@Test
	void aP1363ShapedSignatureInTheDerPositionFails() throws Exception {
		KeyPair ca = ecKeyPair();
		byte[] digest = digest32();
		byte[] p1363 = p1363SignatureBy(ca.getPrivate(), digest);

		AwsKmsSigner signer = new AwsKmsSigner(clientReturning(responseOf(p1363)), (ECPublicKey) ca.getPublic(), KEY);

		assertThatThrownBy(() -> signer.signDigestDer(digest)).isInstanceOf(KmsSigningException.class)
				.hasMessageContaining("does not verify against the pinned public key");
	}

	/**
	 * A truncated DER body is the failure a length check alone would miss: the
	 * outer SEQUENCE header still looks right.
	 */
	@Test
	void aTruncatedSignatureFails() throws Exception {
		KeyPair ca = ecKeyPair();
		byte[] digest = digest32();
		byte[] der = derSignatureBy(ca.getPrivate(), digest);
		byte[] truncated = Arrays.copyOf(der, der.length - 8);

		AwsKmsSigner signer = new AwsKmsSigner(clientReturning(responseOf(truncated)), (ECPublicKey) ca.getPublic(),
				KEY);

		assertThatThrownBy(() -> signer.signDigestDer(digest)).isInstanceOf(KmsSigningException.class)
				.hasMessageContaining("does not verify against the pinned public key");
	}

	@Test
	void anEmptySignatureFails() {
		KeyPair ca = ecKeyPair();

		AwsKmsSigner signer = new AwsKmsSigner(clientReturning(responseOf(new byte[0])), (ECPublicKey) ca.getPublic(),
				KEY);

		assertThatThrownBy(() -> signer.signDigestDer(digest32())).isInstanceOf(KmsSigningException.class)
				.hasMessageContaining("does not verify against the pinned public key");
	}

	/**
	 * The SDK models the signature as optional, so an absent one arrives as a null
	 * — a signing refusal naming the key, not a {@link NullPointerException} from
	 * somewhere in the middle of the guard chain.
	 */
	@Test
	void aResponseWithNoSignatureAtAllFails() {
		SignResponse empty = SignResponse.builder().keyId(KEY_ARN).signingAlgorithm(SigningAlgorithmSpec.ECDSA_SHA_256)
				.build();

		AwsKmsSigner signer = new AwsKmsSigner(clientReturning(empty), (ECPublicKey) ecKeyPair().getPublic(), KEY);

		assertThatThrownBy(() -> signer.signDigestDer(digest32())).isInstanceOf(KmsSigningException.class)
				.hasMessageContaining("no signature").hasMessageContaining(KEY.redacted());
	}

	/**
	 * A response attributed to another key is refused even though it would verify:
	 * the local check answers "is this the pinned key's signature", and this one
	 * answers "did the service think it was signing with the pinned key". Both have
	 * to hold, or a key policy or endpoint that quietly substitutes a key is
	 * visible only in whichever check happens to notice.
	 */
	@Test
	void aResponseAttributedToADifferentKeyIsRefusedEvenWhenItVerifies() throws Exception {
		KeyPair ca = ecKeyPair();
		byte[] digest = digest32();
		SignResponse response = SignResponse.builder()
				.keyId("arn:aws:kms:us-east-1:111122223333:key/99998888-7777-6666-5555-444433332222")
				.signingAlgorithm(SigningAlgorithmSpec.ECDSA_SHA_256)
				.signature(SdkBytes.fromByteArray(derSignatureBy(ca.getPrivate(), digest))).build();

		AwsKmsSigner signer = new AwsKmsSigner(clientReturning(response), (ECPublicKey) ca.getPublic(), KEY);

		assertThatThrownBy(() -> signer.signDigestDer(digest)).isInstanceOf(KmsSigningException.class)
				.hasMessageContaining("attributed to a different key").hasMessageNotContaining("99998888");
	}

	@Test
	void aResponseUnderADifferentSigningAlgorithmIsRefusedEvenWhenItVerifies() throws Exception {
		KeyPair ca = ecKeyPair();
		byte[] digest = digest32();
		SignResponse response = SignResponse.builder().keyId(KEY_ARN)
				.signingAlgorithm(SigningAlgorithmSpec.ECDSA_SHA_512)
				.signature(SdkBytes.fromByteArray(derSignatureBy(ca.getPrivate(), digest))).build();

		AwsKmsSigner signer = new AwsKmsSigner(clientReturning(response), (ECPublicKey) ca.getPublic(), KEY);

		assertThatThrownBy(() -> signer.signDigestDer(digest)).isInstanceOf(KmsSigningException.class)
				.hasMessageContaining("ECDSA_SHA_512").hasMessageContaining("not ECDSA_SHA_256");
	}

	/**
	 * A disabled or pending-deletion key is an SDK exception, and its message is a
	 * KMS response body: useful in a stack trace, never in a message that can reach
	 * an API error or a span.
	 */
	@Test
	void aKmsFailureIsWrappedWithoutTheUnderlyingMessage() {
		KmsClient kms = mock(KmsClient.class);
		when(kms.sign(any(SignRequest.class)))
				.thenThrow(KmsInvalidStateException.builder().message("arn:aws:kms:secret-detail is disabled").build());

		AwsKmsSigner signer = new AwsKmsSigner(kms, (ECPublicKey) ecKeyPair().getPublic(), KEY);

		assertThatThrownBy(() -> signer.signDigestDer(digest32())).isInstanceOf(KmsSigningException.class)
				.hasMessageContaining(KEY.redacted()).hasMessageContaining("KmsInvalidStateException")
				.hasMessageNotContaining("secret-detail").hasCauseInstanceOf(KmsInvalidStateException.class);
	}
}
