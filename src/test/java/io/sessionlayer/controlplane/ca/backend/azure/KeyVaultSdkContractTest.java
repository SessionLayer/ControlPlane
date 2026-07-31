package io.sessionlayer.controlplane.ca.backend.azure;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.azure.core.credential.AccessToken;
import com.azure.core.credential.TokenCredential;
import com.azure.core.credential.TokenRequestContext;
import com.azure.core.exception.HttpResponseException;
import com.azure.core.http.HttpClient;
import com.azure.core.http.jdk.httpclient.JdkHttpClientBuilder;
import com.azure.security.keyvault.keys.KeyClient;
import com.azure.security.keyvault.keys.KeyClientBuilder;
import com.azure.security.keyvault.keys.cryptography.CryptographyClient;
import com.azure.security.keyvault.keys.cryptography.CryptographyClientBuilder;
import com.azure.security.keyvault.keys.cryptography.models.SignResult;
import com.azure.security.keyvault.keys.cryptography.models.SignatureAlgorithm;
import com.azure.security.keyvault.keys.models.KeyVaultKey;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.sessionlayer.controlplane.ca.CaKeyType;
import io.sessionlayer.controlplane.ca.backend.azure.testkv.KeyVaultRestDouble;
import io.sessionlayer.controlplane.ca.backend.azure.testkv.KeyVaultRestDouble.FaultMode;
import io.sessionlayer.controlplane.ca.backend.azure.testkv.KeyVaultRestDouble.RecordedRequest;
import io.sessionlayer.controlplane.ca.mtls.X509Certificates;
import io.sessionlayer.controlplane.ca.sign.EcdsaSignatures;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.time.OffsetDateTime;
import java.util.Base64;
import java.util.List;
import javax.net.ssl.SSLContext;
import javax.net.ssl.X509TrustManager;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import reactor.core.publisher.Mono;

/**
 * Drives the genuine Azure SDK ({@code CryptographyClient}/{@code KeyClient})
 * against {@link KeyVaultRestDouble}. This is deliberately not a test of our
 * own {@code KeyVaultSigner} seam:
 * {@code io.sessionlayer.controlplane.ca.CloudBackendNormalizationTest} in this
 * module already covers the normalization with a hand-written double, which
 * never touches request shape, auth, or encoding. This class proves the wire
 * contract the seam depends on.
 */
class KeyVaultSdkContractTest {

	private static final ObjectMapper MAPPER = new ObjectMapper();

	private KeyVaultRestDouble vault;
	private HttpClient httpClient;
	private FakeTokenCredential credential;
	private CryptographyClient cryptographyClient;

	@BeforeEach
	void setUp() throws Exception {
		vault = new KeyVaultRestDouble();
		httpClient = trustingHttpClient(vault.tlsCertificate());
		credential = new FakeTokenCredential();
		cryptographyClient = cryptographyClientBuilder().buildClient();
	}

	@AfterEach
	void tearDown() {
		vault.close();
	}

	private CryptographyClientBuilder cryptographyClientBuilder() {
		return new CryptographyClientBuilder().keyIdentifier(vault.keyIdentifier()).credential(credential)
				.httpClient(httpClient)
				// The double is addressed as an IP literal (127.0.0.1); Key Vault's own
				// anti-phishing check (KeyVaultCredentialPolicy#isChallengeResourceValid) only
				// ever
				// matches a challenge "resource" that is a strict parent-domain suffix of the
				// request host (e.g. "vault.azure.net" under "my-vault.vault.azure.net") — an
				// IP-literal host can never satisfy that, by the check's own design. The SDK
				// documents this exact flag as the escape hatch for a non-Azure-domain
				// endpoint;
				// it does not touch TLS/certificate validation, which stays fully enforced
				// below.
				.disableChallengeResourceVerification();
	}

	private static HttpClient trustingHttpClient(X509Certificate certificate) throws Exception {
		X509TrustManager trustManager = X509Certificates.trustManagerFor(certificate);
		SSLContext trustContext = SSLContext.getInstance("TLSv1.3");
		trustContext.init(null, new javax.net.ssl.TrustManager[]{trustManager}, new SecureRandom());
		java.net.http.HttpClient.Builder jdkBuilder = java.net.http.HttpClient.newBuilder().sslContext(trustContext);
		return new JdkHttpClientBuilder(jdkBuilder).build();
	}

	private static byte[] digestOf(String data) throws Exception {
		return MessageDigest.getInstance("SHA-256").digest(data.getBytes(StandardCharsets.UTF_8));
	}

	@Test
	void signRoundTripsThroughTheGenuineSdkWithAVerifiableP1363Signature() throws Exception {
		byte[] digest = digestOf("happy-path");

		SignResult result = cryptographyClient.sign(SignatureAlgorithm.ES256, digest);

		assertThat(result.getSignature()).hasSize(64);
		assertVerifies(result.getSignature(), digest, vault.publicKey());

		List<RecordedRequest> requests = vault.recordedRequests();
		assertThat(requests).isNotEmpty();
		RecordedRequest signRequest = requests.stream().filter(r -> r.path().endsWith("/sign"))
				.reduce((first, last) -> last).orElseThrow(() -> new AssertionError("no /sign request recorded"));
		assertThat(signRequest.method()).isEqualTo("POST");
		assertThat(signRequest.apiVersion()).isNotBlank();
		assertThat(signRequest.bearerTokenPresent()).isTrue();

		JsonNode body = MAPPER.readTree(signRequest.body());
		assertThat(body.get("alg").asText()).isEqualTo("ES256");
		assertThat(Base64.getUrlDecoder().decode(body.get("value").asText())).isEqualTo(digest);

		// The bearer challenge actually ran, and ran exactly the way the real SDK
		// runs it: KeyVaultCredentialPolicy sends the first request to a new
		// authority with no cached challenge unauthenticated *and with its real
		// body withheld* (stashed, replaced by Content-Length: 0), learns the
		// scope from the 401, then replays the original request — now carrying
		// both the bearer token and the withheld body. An unconditionally-trusting
		// double would never exercise any of that and would prove nothing.
		int firstBearer = indexOfFirst(requests, RecordedRequest::bearerTokenPresent);
		assertThat(firstBearer).isGreaterThan(0);
		assertThat(requests.get(0).bearerTokenPresent()).isFalse();
		assertThat(requests.get(0).body()).isEmpty();
	}

	@Test
	void keyClientResolvesTheEcPublicKeyIncludingALeadingZeroCoordinate() throws Exception {
		KeyPair leadingZero = keyPairWithALeadingZeroCoordinate();
		try (KeyVaultRestDouble leadingZeroVault = new KeyVaultRestDouble(leadingZero)) {
			HttpClient client = trustingHttpClient(leadingZeroVault.tlsCertificate());
			KeyClient keyClient = new KeyClientBuilder().vaultUrl(leadingZeroVault.baseUrl()).credential(credential)
					.httpClient(client).disableChallengeResourceVerification().buildClient();

			KeyVaultKey vaultKey = keyClient.getKey(leadingZeroVault.keyName(), leadingZeroVault.keyVersion());
			KeyPair resolved = vaultKey.getKey().toEc(false);

			assertThat(((ECPublicKey) resolved.getPublic()).getW())
					.isEqualTo(((ECPublicKey) leadingZero.getPublic()).getW());
		}
	}

	private static KeyPair keyPairWithALeadingZeroCoordinate() throws Exception {
		KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
		generator.initialize(new ECGenParameterSpec("secp256r1"));
		for (int attempt = 0; attempt < 10_000; attempt++) {
			KeyPair pair = generator.generateKeyPair();
			ECPublicKey pub = (ECPublicKey) pair.getPublic();
			if (pub.getW().getAffineX().toByteArray().length > 32
					|| pub.getW().getAffineY().toByteArray().length > 32) {
				return pair;
			}
		}
		throw new AssertionError("did not find a P-256 key with a leading-zero coordinate in 10000 attempts");
	}

	@Test
	void fromP1363DecodesTheRealShapeAndRejectsDer() throws Exception {
		byte[] digest = digestOf("der-vs-p1363-discrimination");

		byte[] p1363 = cryptographyClient.sign(SignatureAlgorithm.ES256, digest).getSignature();
		assertThat(EcdsaSignatures.fromP1363(p1363, CaKeyType.ECDSA_NISTP256)).isNotNull();
		assertVerifies(p1363, digest, vault.publicKey());

		vault.setFaultMode(FaultMode.RETURN_DER);
		byte[] der = cryptographyClient.sign(SignatureAlgorithm.ES256, digest).getSignature();
		assertThatThrownBy(() -> EcdsaSignatures.fromP1363(der, CaKeyType.ECDSA_NISTP256))
				.isInstanceOf(IllegalArgumentException.class).hasMessageContaining("P1363 signature length");
	}

	@Test
	void unreachableVaultFailsTheSigningCall() throws Exception {
		KeyVaultRestDouble stopped = new KeyVaultRestDouble();
		String keyIdentifier = stopped.keyIdentifier();
		HttpClient clientTransport = trustingHttpClient(stopped.tlsCertificate());
		stopped.close();

		CryptographyClient client = new CryptographyClientBuilder().keyIdentifier(keyIdentifier).credential(credential)
				.httpClient(clientTransport).disableChallengeResourceVerification().buildClient();

		assertThatThrownBy(() -> client.sign(SignatureAlgorithm.ES256, digestOf("vault-unreachable")))
				.isInstanceOf(RuntimeException.class);
	}

	@Test
	void credentialRejectedFailsWith401() throws Exception {
		vault.setFaultMode(FaultMode.CREDENTIAL_REJECTED);
		assertThatThrownBy(() -> cryptographyClient.sign(SignatureAlgorithm.ES256, digestOf("credential-rejected")))
				.isInstanceOf(HttpResponseException.class)
				.satisfies(e -> assertThat(((HttpResponseException) e).getResponse().getStatusCode()).isEqualTo(401));
	}

	@Test
	void keyDisabledFailsWith403() throws Exception {
		vault.setFaultMode(FaultMode.KEY_DISABLED);
		assertThatThrownBy(() -> cryptographyClient.sign(SignatureAlgorithm.ES256, digestOf("key-disabled")))
				.isInstanceOf(HttpResponseException.class)
				.satisfies(e -> assertThat(((HttpResponseException) e).getResponse().getStatusCode()).isEqualTo(403));
	}

	@Test
	void keyNotFoundFailsWith404() throws Exception {
		vault.setFaultMode(FaultMode.KEY_NOT_FOUND);
		assertThatThrownBy(() -> cryptographyClient.sign(SignatureAlgorithm.ES256, digestOf("key-not-found")))
				.isInstanceOf(HttpResponseException.class)
				.satisfies(e -> assertThat(((HttpResponseException) e).getResponse().getStatusCode()).isEqualTo(404));
	}

	@Test
	void wrongAlgorithmFailsWith400() throws Exception {
		assertThatThrownBy(() -> cryptographyClient.sign(SignatureAlgorithm.RS256, digestOf("wrong-algorithm")))
				.isInstanceOf(HttpResponseException.class)
				.satisfies(e -> assertThat(((HttpResponseException) e).getResponse().getStatusCode()).isEqualTo(400));
	}

	@Test
	void truncatedSignatureFailsFromP1363() throws Exception {
		vault.setFaultMode(FaultMode.RETURN_TRUNCATED);
		byte[] signature = cryptographyClient.sign(SignatureAlgorithm.ES256, digestOf("truncated-signature"))
				.getSignature();
		assertThatThrownBy(() -> EcdsaSignatures.fromP1363(signature, CaKeyType.ECDSA_NISTP256))
				.isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	void overlongSignatureFailsFromP1363() throws Exception {
		vault.setFaultMode(FaultMode.RETURN_OVERLONG);
		byte[] signature = cryptographyClient.sign(SignatureAlgorithm.ES256, digestOf("overlong-signature"))
				.getSignature();
		assertThatThrownBy(() -> EcdsaSignatures.fromP1363(signature, CaKeyType.ECDSA_NISTP256))
				.isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	void wrongKeySignatureDecodesButFailsVerification() throws Exception {
		vault.setFaultMode(FaultMode.RETURN_WRONG_KEY);
		byte[] digest = digestOf("wrong-key-signature");
		byte[] signature = cryptographyClient.sign(SignatureAlgorithm.ES256, digest).getSignature();

		// Shape alone says nothing: it decodes cleanly (64 bytes) yet was never
		// produced by the pinned key — only an actual verify catches it.
		EcdsaSignatures.RS rs = EcdsaSignatures.fromP1363(signature, CaKeyType.ECDSA_NISTP256);
		assertThat(rs).isNotNull();

		Signature verifier = Signature.getInstance("NONEwithECDSA");
		verifier.initVerify(vault.publicKey());
		verifier.update(digest);
		assertThat(verifier.verify(EcdsaSignatures.toDer(rs))).isFalse();
	}

	private static void assertVerifies(byte[] p1363Signature, byte[] digest, ECPublicKey publicKey) throws Exception {
		EcdsaSignatures.RS rs = EcdsaSignatures.fromP1363(p1363Signature, CaKeyType.ECDSA_NISTP256);
		Signature verifier = Signature.getInstance("NONEwithECDSA");
		verifier.initVerify(publicKey);
		verifier.update(digest);
		assertThat(verifier.verify(EcdsaSignatures.toDer(rs))).isTrue();
	}

	private static int indexOfFirst(List<RecordedRequest> requests, java.util.function.Predicate<RecordedRequest> p) {
		for (int i = 0; i < requests.size(); i++) {
			if (p.test(requests.get(i))) {
				return i;
			}
		}
		return -1;
	}

	/**
	 * Only the token *issuer* is faked here: the header path (challenge parsing,
	 * {@code Authorization: Bearer}, retry) is the genuine
	 * {@code BearerTokenAuthenticationPolicy}.
	 */
	private static final class FakeTokenCredential implements TokenCredential {
		@Override
		public Mono<AccessToken> getToken(TokenRequestContext request) {
			return Mono.just(new AccessToken("test-access-token", OffsetDateTime.now().plusHours(1)));
		}
	}
}
