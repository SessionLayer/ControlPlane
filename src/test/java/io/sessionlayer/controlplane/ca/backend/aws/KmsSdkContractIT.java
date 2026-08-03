package io.sessionlayer.controlplane.ca.backend.aws;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.catchThrowable;

import com.sun.net.httpserver.HttpServer;
import io.sessionlayer.controlplane.ca.CaKeyProvisioner;
import io.sessionlayer.controlplane.ca.CaKeyType;
import io.sessionlayer.controlplane.ca.backend.aws.AwsKmsSigner.KmsSigningException;
import io.sessionlayer.controlplane.ca.sign.EcdsaSignatures;
import io.sessionlayer.controlplane.data.runtime.CaKeyMaterial;
import java.io.IOException;
import java.math.BigInteger;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.Signature;
import java.security.interfaces.ECPublicKey;
import java.time.Duration;
import java.util.Arrays;
import java.util.Base64;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import software.amazon.awssdk.core.exception.SdkException;
import software.amazon.awssdk.services.kms.model.DisabledException;
import software.amazon.awssdk.services.kms.model.GetPublicKeyResponse;
import software.amazon.awssdk.services.kms.model.KeySpec;
import software.amazon.awssdk.services.kms.model.KmsException;
import software.amazon.awssdk.services.kms.model.KmsInvalidStateException;
import software.amazon.awssdk.services.kms.model.SigningAlgorithmSpec;

/**
 * The {@code aws_kms} seam driven against {@link LocalStackKms} — a KMS that
 * really generates keys and really signs, reached over the real AWS protocol by
 * the genuine SDK. {@code AwsKmsSignerTest} covers the same guards with a
 * mocked {@code KmsClient}, which never touches request signing, endpoint
 * resolution, the credential chain, or the SDK's response unmarshalling; this
 * class proves the wire contract those guards are written against.
 *
 * <p>
 * The failures a real KMS cannot be made to produce are the exceptions, and
 * each one says so where it is used: LocalStack's community edition evaluates
 * no IAM policy, and no service returns a signature in the wrong encoding or a
 * truncated one.
 */
class KmsSdkContractIT {

	private static AwsKmsSignerFactory factory;
	private static String keyArn;
	private static KmsKeyArn key;
	private static ECPublicKey publicKey;

	@BeforeAll
	static void adoptAKmsKey() {
		factory = new AwsKmsSignerFactory(LocalStackKms.properties());
		keyArn = LocalStackKms.createSigningKey();
		key = KmsKeyArn.parse(keyArn, factory.anchor());
		publicKey = factory.fetchPublicKey(key);
	}

	@AfterAll
	static void releaseTheClient() {
		factory.close();
	}

	/**
	 * Adoption's one KMS read, against a real response.
	 * {@code validateSigningKey} compares the echoed {@code KeyId} to the requested
	 * ARN, so a service that answered with a bare key id would fail every adoption
	 * — a check worth making against bytes KMS produced rather than against a
	 * builder someone filled in.
	 */
	@Test
	void getPublicKeyEchoesTheFullArnAndResolvesTheKeyThatSigns() throws Exception {
		GetPublicKeyResponse response = LocalStackKms.admin().getPublicKey(request -> request.keyId(keyArn));

		assertThat(response.keyId()).isEqualTo(keyArn);
		assertThat(response.keySpec()).isEqualTo(KeySpec.ECC_NIST_P256);
		assertThat(response.signingAlgorithms()).contains(SigningAlgorithmSpec.ECDSA_SHA_256);
		assertThat(publicKey.getEncoded()).isEqualTo(response.publicKey().asByteArray());

		byte[] digest = digestOf("resolved-key-is-the-signing-key");
		assertVerifies(factory.signerFor(key, publicKey).signDigestDer(digest), digest, publicKey);
	}

	/**
	 * The encoding claim, made against the bytes KMS really sent: a DER
	 * {@code SEQUENCE} that round-trips through the strict reader
	 * {@code KmsCaBackend} normalizes with.
	 */
	@Test
	void theSignatureRealKmsReturnsIsDer() throws Exception {
		byte[] digest = digestOf("aws-kms-happy-path");

		byte[] signature = factory.signerFor(key, publicKey).signDigestDer(digest);

		assertThat(signature[0]).isEqualTo((byte) 0x30);
		EcdsaSignatures.RS rs = EcdsaSignatures.fromDer(signature);
		assertThat(EcdsaSignatures.toDer(rs)).isEqualTo(signature);
		assertVerifies(signature, digest, publicKey);
	}

	/**
	 * The discrimination {@code EcdsaSignatures.fromDer} exists for. The same
	 * signature is re-encoded as P1363 {@code r||s} and returned in the position
	 * the DER one occupied: a build that had lost the DER reader would take it and
	 * mint a certificate no node could verify, so a test that passed on either
	 * encoding would prove nothing.
	 */
	@Test
	void theSameSignatureReencodedAsP1363IsRefusedInTheDerPosition() throws Exception {
		byte[] digest = digestOf("der-vs-p1363-discrimination");
		byte[] der = factory.signerFor(key, publicKey).signDigestDer(digest);
		EcdsaSignatures.RS rs = EcdsaSignatures.fromDer(der);
		byte[] p1363 = toP1363(rs);

		// Same (r, s) as the DER form, so nothing below can be passing because the
		// signature itself is broken — only the encoding differs.
		assertThat(EcdsaSignatures.fromP1363(p1363, CaKeyType.ECDSA_NISTP256)).isEqualTo(rs);
		assertThat(p1363).hasSize(64).isNotEqualTo(der);
		assertThatThrownBy(() -> EcdsaSignatures.fromDer(p1363)).isInstanceOf(IllegalArgumentException.class);

		try (KmsEndpoint endpoint = KmsEndpoint.returningSignature(keyArn, p1363);
				AwsKmsSignerFactory pointed = new AwsKmsSignerFactory(LocalStackKms.propertiesFor(endpoint.url()))) {
			assertThatThrownBy(() -> pointed.signerFor(key, publicKey).signDigestDer(digest))
					.isInstanceOf(KmsSigningException.class)
					.hasMessageContaining("does not verify against the pinned public key");
		}
	}

	/**
	 * Two real keys, one real signature: KMS signs with the key the signer names
	 * while the pinned public half belongs to another, so the refusal comes from an
	 * actual verification failure rather than from a response anyone edited. This
	 * is the case a "does the response look like a signature" check would pass.
	 */
	@Test
	void aSignatureRealKmsMadeWithAnotherKeyIsRefusedByThePinnedKeyGuard() {
		KmsKeyArn other = KmsKeyArn.parse(LocalStackKms.createSigningKey(), factory.anchor());

		KmsSigner signer = factory.signerFor(other, publicKey);

		assertThatThrownBy(() -> signer.signDigestDer(digestOf("wrong-key"))).isInstanceOf(KmsSigningException.class)
				.hasMessageContaining("does not verify against the pinned public key")
				.hasMessageContaining(other.redacted()).hasMessageNotContaining(LocalStackKms.ACCOUNT_ID);
	}

	@Test
	void anUnreachableKmsFailsClosed() throws Exception {
		AwsKmsProperties properties = LocalStackKms.propertiesFor(closedEndpoint());
		properties.setTimeout(Duration.ofSeconds(2));

		try (AwsKmsSignerFactory pointed = new AwsKmsSignerFactory(properties)) {
			assertThatThrownBy(() -> pointed.signerFor(key, publicKey).signDigestDer(digestOf("kms-unreachable")))
					.isInstanceOf(KmsSigningException.class).hasMessageContaining(key.redacted())
					.hasCauseInstanceOf(SdkException.class);
		}
	}

	/**
	 * LocalStack's community edition evaluates no IAM policy — a request carrying
	 * an invalid credential is served exactly as a valid one is — so the rejection
	 * is the one response here that a local KMS cannot produce. The SDK's own error
	 * unmarshaller turns the wire form into the {@link KmsException} the guard sees
	 * in production.
	 */
	@Test
	void aRejectedCredentialFailsClosed() throws Exception {
		try (KmsEndpoint endpoint = KmsEndpoint.returningError(400, "UnrecognizedClientException",
				"The security token included in the request is invalid.");
				AwsKmsSignerFactory pointed = new AwsKmsSignerFactory(LocalStackKms.propertiesFor(endpoint.url()))) {

			Throwable thrown = catchThrowable(
					() -> pointed.signerFor(key, publicKey).signDigestDer(digestOf("credential-rejected")));

			assertThat(thrown).isInstanceOf(KmsSigningException.class).hasMessageContaining(key.redacted())
					.hasCauseInstanceOf(KmsException.class);
			assertThat(((KmsException) thrown.getCause()).awsErrorDetails().errorCode())
					.isEqualTo("UnrecognizedClientException");
		}
	}

	/**
	 * KMS names the key in its own error, ARN and account id included. That message
	 * is the cause's, and it stays there: the exception SessionLayer logs at WARN
	 * on every signing refusal carries the redacted form only.
	 */
	@Test
	void aDisabledKeyFailsClosedWithoutWritingTheAccountIdIntoTheFailure() {
		KmsKeyArn disabled = KmsKeyArn.parse(LocalStackKms.createSigningKey(), factory.anchor());
		ECPublicKey pinned = factory.fetchPublicKey(disabled);
		LocalStackKms.disable(disabled.keyArn());

		Throwable thrown = catchThrowable(
				() -> factory.signerFor(disabled, pinned).signDigestDer(digestOf("key-disabled")));

		assertThat(thrown).isInstanceOf(KmsSigningException.class).hasMessageContaining(disabled.redacted())
				.hasCauseInstanceOf(DisabledException.class);
		assertThat(thrown.getCause()).hasMessageContaining(LocalStackKms.ACCOUNT_ID);
		assertThat(thrown.getMessage()).doesNotContain(LocalStackKms.ACCOUNT_ID);
	}

	@Test
	void aKeyPendingDeletionFailsClosed() {
		KmsKeyArn doomed = KmsKeyArn.parse(LocalStackKms.createSigningKey(), factory.anchor());
		ECPublicKey pinned = factory.fetchPublicKey(doomed);
		LocalStackKms.scheduleDeletion(doomed.keyArn());

		assertThatThrownBy(() -> factory.signerFor(doomed, pinned).signDigestDer(digestOf("key-pending-deletion")))
				.isInstanceOf(KmsSigningException.class).hasMessageContaining(doomed.redacted())
				.hasCauseInstanceOf(KmsInvalidStateException.class).hasMessageNotContaining(LocalStackKms.ACCOUNT_ID);
	}

	/**
	 * The signer always asks for {@code ECDSA_SHA_256} and this key offers only
	 * {@code ECDSA_SHA_384}. Reaching this at all means the key behind an adopted
	 * ARN changed shape after adoption refused that shape, so what is under test is
	 * that no signature comes back either way — whether KMS refuses the algorithm
	 * or answers with a signature the pinned key cannot verify.
	 */
	@Test
	void signingWithAnAlgorithmTheKeyDoesNotOfferFailsClosed() {
		KmsKeyArn p384 = KmsKeyArn.parse(LocalStackKms.createKey(KeySpec.ECC_NIST_P384), factory.anchor());

		assertThatThrownBy(() -> factory.signerFor(p384, publicKey).signDigestDer(digestOf("wrong-algorithm")))
				.isInstanceOf(KmsSigningException.class).hasMessageContaining(p384.redacted())
				.hasMessageNotContaining(LocalStackKms.ACCOUNT_ID);
	}

	/**
	 * A truncated signature keeps a well-formed {@code SEQUENCE} header, so it is
	 * the failure a shape check passes and only a verification catches.
	 */
	@Test
	void aTruncatedSignatureFailsClosed() throws Exception {
		byte[] digest = digestOf("truncated-signature");
		byte[] der = factory.signerFor(key, publicKey).signDigestDer(digest);
		byte[] truncated = Arrays.copyOf(der, der.length - 8);

		try (KmsEndpoint endpoint = KmsEndpoint.returningSignature(keyArn, truncated);
				AwsKmsSignerFactory pointed = new AwsKmsSignerFactory(LocalStackKms.propertiesFor(endpoint.url()))) {
			assertThatThrownBy(() -> pointed.signerFor(key, publicKey).signDigestDer(digest))
					.isInstanceOf(KmsSigningException.class)
					.hasMessageContaining("does not verify against the pinned public key");
		}
	}

	/**
	 * The refusal reaches the CA backend as a refusal: {@code KmsCaBackend} hashes,
	 * delegates and normalizes, and a signing failure has to come out of it rather
	 * than becoming an empty or partial signature the certificate assembler would
	 * happily encode.
	 */
	@Test
	void aRefusedSignatureLeavesTheCaBackendWithNothingToNormalize() {
		KmsKeyArn disabled = KmsKeyArn.parse(LocalStackKms.createSigningKey(), factory.anchor());
		ECPublicKey pinned = factory.fetchPublicKey(disabled);
		LocalStackKms.disable(disabled.keyArn());
		KmsCaBackend backend = new KmsCaBackend(CaKeyType.ECDSA_NISTP256, factory.signerFor(disabled, pinned));

		assertThatThrownBy(() -> backend.sign("to-be-signed".getBytes(StandardCharsets.UTF_8)))
				.isInstanceOf(KmsSigningException.class);
	}

	@Test
	void theProvisionerAdoptsARealKmsKeyAndPersistsNoPrivateMaterial() {
		String arn = LocalStackKms.createSigningKey();

		CaKeyProvisioner.Provisioned provisioned = new AwsKmsCaProvisioner(factory)
				.provision(new CaKeyProvisioner.Request("session", "session-ca-kms", "active", arn, "ecdsa-p256"));

		assertThat(provisioned.config().backend()).isEqualTo("aws_kms");
		assertThat(provisioned.config().keyReference()).isEqualTo(arn);
		assertThat(provisioned.material().keyLocation()).isEqualTo(CaKeyMaterial.EXTERNAL);
		assertThat(provisioned.material().wrappedKey()).isNull();
		assertThat(provisioned.material().iv()).isNull();
		assertThat(provisioned.material().kekReference()).isNull();
		assertThat(provisioned.material().publicKey())
				.isEqualTo(factory.fetchPublicKey(KmsKeyArn.parse(arn, factory.anchor())).getEncoded());
	}

	@Test
	void theProvisionerRefusesAKeyThatCannotProduceEcdsaSha256() {
		KmsKeyArn rsa = KmsKeyArn.parse(LocalStackKms.createKey(KeySpec.RSA_2048), factory.anchor());

		assertThatThrownBy(() -> factory.fetchPublicKey(rsa)).isInstanceOf(IllegalStateException.class)
				.hasMessageContaining("not ECC_NIST_P256").hasMessageContaining(rsa.redacted())
				.hasMessageNotContaining(LocalStackKms.ACCOUNT_ID);
	}

	/**
	 * KMS resolves the alias perfectly well, which is what makes refusing it a
	 * decision rather than a limitation: {@code kms:UpdateAlias} repoints it at
	 * another key with nothing SessionLayer can see changing, while every node's
	 * {@code TrustedUserCAKeys} still carries the old public half.
	 */
	@Test
	void anAliasIsRefusedEvenThoughKmsWouldServeIt() {
		String arn = LocalStackKms.createSigningKey();
		String alias = LocalStackKms.createAlias(arn);

		assertThat(LocalStackKms.admin().getPublicKey(request -> request.keyId(alias)).keyId()).isEqualTo(arn);

		assertThatThrownBy(() -> new AwsKmsCaProvisioner(factory)
				.provision(new CaKeyProvisioner.Request("session", "session-ca-alias", "active", alias, "ecdsa-p256")))
				.isInstanceOf(KmsKeyArn.InvalidKeyReference.class).hasMessageContaining("is a KMS alias");
	}

	private static byte[] digestOf(String data) throws Exception {
		return MessageDigest.getInstance("SHA-256").digest(data.getBytes(StandardCharsets.UTF_8));
	}

	private static void assertVerifies(byte[] derSignature, byte[] digest, ECPublicKey pinned) throws Exception {
		Signature verifier = Signature.getInstance("NONEwithECDSA");
		verifier.initVerify(pinned);
		verifier.update(digest);
		assertThat(verifier.verify(derSignature)).isTrue();
	}

	private static byte[] toP1363(EcdsaSignatures.RS rs) {
		byte[] out = new byte[64];
		writeFixedWidth(rs.r(), out, 0);
		writeFixedWidth(rs.s(), out, 32);
		return out;
	}

	private static void writeFixedWidth(BigInteger value, byte[] out, int offset) {
		byte[] raw = value.toByteArray();
		int start = Math.max(0, raw.length - 32);
		int len = raw.length - start;
		System.arraycopy(raw, start, out, offset + (32 - len), len);
	}

	/** A port nothing is listening on, for the KMS-unreachable case. */
	private static String closedEndpoint() throws IOException {
		try (ServerSocket socket = new ServerSocket(0, 1, InetAddress.getLoopbackAddress())) {
			return "http://" + urlHost(socket.getInetAddress()) + ":" + socket.getLocalPort();
		}
	}

	/** An IPv6 loopback has to be bracketed before it is a URL host. */
	private static String urlHost(InetAddress address) {
		String literal = address.getHostAddress();
		return literal.contains(":") ? "[" + literal + "]" : literal;
	}

	/**
	 * A KMS endpoint that answers with bytes no real KMS would send. Only the
	 * response body is crafted; everything that reads it — the SDK's protocol and
	 * error unmarshallers, then {@link AwsKmsSigner}'s guards — is the production
	 * path.
	 */
	private static final class KmsEndpoint implements AutoCloseable {

		private static final String AWS_JSON = "application/x-amz-json-1.1";

		private final HttpServer server;

		private KmsEndpoint(int status, byte[] body, String errorType) throws IOException {
			this.server = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
			this.server.createContext("/", exchange -> {
				try {
					exchange.getRequestBody().readAllBytes();
					exchange.getResponseHeaders().add("Content-Type", AWS_JSON);
					if (errorType != null) {
						exchange.getResponseHeaders().add("x-amzn-ErrorType", errorType);
					}
					exchange.sendResponseHeaders(status, body.length);
					exchange.getResponseBody().write(body);
				} finally {
					exchange.close();
				}
			});
			this.server.start();
		}

		static KmsEndpoint returningSignature(String respondingKeyArn, byte[] signature) throws IOException {
			String body = "{\"KeyId\":\"" + respondingKeyArn + "\",\"SigningAlgorithm\":\"ECDSA_SHA_256\""
					+ ",\"Signature\":\"" + Base64.getEncoder().encodeToString(signature) + "\"}";
			return new KmsEndpoint(200, body.getBytes(StandardCharsets.UTF_8), null);
		}

		static KmsEndpoint returningError(int status, String errorCode, String message) throws IOException {
			String body = "{\"__type\":\"" + errorCode + "\",\"message\":\"" + message + "\"}";
			return new KmsEndpoint(status, body.getBytes(StandardCharsets.UTF_8), errorCode);
		}

		String url() {
			return "http://" + urlHost(server.getAddress().getAddress()) + ":" + server.getAddress().getPort();
		}

		@Override
		public void close() {
			server.stop(0);
		}
	}
}
