package io.sessionlayer.controlplane.ca.backend.aws;

import jakarta.annotation.PreDestroy;
import java.net.URI;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;
import software.amazon.awssdk.auth.credentials.DefaultCredentialsProvider;
import software.amazon.awssdk.http.SdkHttpClient;
import software.amazon.awssdk.http.apache5.Apache5HttpClient;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.KmsClientBuilder;
import software.amazon.awssdk.services.kms.model.GetPublicKeyRequest;
import software.amazon.awssdk.services.kms.model.GetPublicKeyResponse;
import software.amazon.awssdk.services.kms.model.KeySpec;
import software.amazon.awssdk.services.kms.model.KeyUsageType;
import software.amazon.awssdk.services.kms.model.SigningAlgorithmSpec;

/**
 * Builds {@link KmsSigner}s and resolves adoption-time public keys. Present
 * only when {@code sessionlayer.ca.aws.enabled=true} — its absence as a bean IS
 * the "AWS KMS support not configured" branch {@code CaSignerService} refuses
 * on, so there is nothing here that quietly degrades.
 *
 * <p>
 * The credential chain, the HTTP client and the {@link KmsClient} are all built
 * once, at bean construction, and building them does no I/O — the SDK resolves
 * credentials and opens no connection until a request is made (proven by
 * {@code AwsKmsCredentialsSmokeTest}). Signer construction
 * ({@link #signerFor}) is likewise I/O-free: only {@link #fetchPublicKey}, used
 * solely at CA adoption, talks to KMS.
 *
 * <p>
 * One client serves every key, because KMS takes the key id as a per-request
 * parameter rather than binding it into the client — there is nothing per-key
 * to cache, and a pool per CA would be pure overhead. That pool is a real
 * resource, so this bean owns the whole chain's lifecycle: the SDK does not
 * close an HTTP client or a credentials provider it did not itself create.
 */
@Component
@ConditionalOnProperty(prefix = "sessionlayer.ca.aws", name = "enabled", havingValue = "true")
public class AwsKmsSignerFactory implements AutoCloseable {

	private final KmsKeyArn.Anchor anchor;
	private final DefaultCredentialsProvider credentialsProvider;
	private final SdkHttpClient httpClient;
	private final KmsClient kms;

	public AwsKmsSignerFactory(AwsKmsProperties properties) {
		this.anchor = new KmsKeyArn.Anchor(properties.getPartition(), properties.getRegion(),
				properties.getAccountId());
		this.credentialsProvider = DefaultCredentialsProvider.create();
		this.httpClient = Apache5HttpClient.builder().connectionTimeout(properties.getTimeout())
				.socketTimeout(properties.getTimeout()).build();
		this.kms = buildClient(properties, credentialsProvider, httpClient);
	}

	/**
	 * The one account, region and partition this Control Plane signs in — the
	 * allow-list anchor {@link KmsKeyArn} enforces.
	 */
	public KmsKeyArn.Anchor anchor() {
		return anchor;
	}

	/**
	 * A {@link KmsSigner} bound to {@code ref}'s key ARN and
	 * {@code pinnedPublicKey} (read from {@code ca_key_material}, never re-fetched
	 * here).
	 */
	public KmsSigner signerFor(KmsKeyArn ref, ECPublicKey pinnedPublicKey) {
		return new AwsKmsSigner(kms, pinnedPublicKey, ref.keyArn());
	}

	/**
	 * Resolves the public key for {@code ref} directly from KMS. Used only at CA
	 * adoption (rotation onto a KMS key) — every other read of the CA public key is
	 * the persisted {@code ca_key_material.public_key} column, so this is the sole
	 * point where KMS is asked "what is this key", and the only permission this
	 * seam needs beyond {@code kms:Sign}.
	 */
	public ECPublicKey fetchPublicKey(KmsKeyArn ref) {
		GetPublicKeyResponse response = kms.getPublicKey(GetPublicKeyRequest.builder().keyId(ref.keyArn()).build());
		validateSigningKey(response, ref.keyArn());
		return decodeP256PublicKey(response.publicKey().asByteArray(), ref.keyArn());
	}

	/**
	 * Package-visible for {@code AwsKmsSignerFactoryTest}: these checks are pure,
	 * so they are proven without KMS, independent of the network call in
	 * {@link #fetchPublicKey}.
	 *
	 * <p>
	 * The result of {@link #fetchPublicKey} becomes the pinned public key persisted
	 * into {@code ca_key_material}, so this is the one hop in the whole design that
	 * is not otherwise verified: an endpoint, proxy or redirect returning a
	 * different key would silently pin the CA to a key the operator never chose,
	 * and every later signature would then verify against it perfectly. A key that
	 * cannot do {@code ECDSA_SHA_256} is refused here rather than at the first
	 * certificate, because {@code DescribeKey} is deliberately not in this seam's
	 * required IAM surface.
	 */
	static void validateSigningKey(GetPublicKeyResponse response, String keyArn) {
		if (!keyArn.equals(response.keyId())) {
			throw new IllegalStateException(
					"KMS returned a key id that does not match the requested '" + keyArn + "'");
		}
		if (KeySpec.ECC_NIST_P256 != response.keySpec()) {
			throw new IllegalStateException(
					"KMS key '" + keyArn + "' is " + response.keySpec() + ", not ECC_NIST_P256");
		}
		if (KeyUsageType.SIGN_VERIFY != response.keyUsage()) {
			throw new IllegalStateException("KMS key '" + keyArn + "' has usage " + response.keyUsage()
					+ ", not SIGN_VERIFY");
		}
		if (!response.signingAlgorithms().contains(SigningAlgorithmSpec.ECDSA_SHA_256)) {
			throw new IllegalStateException("KMS key '" + keyArn + "' does not offer ECDSA_SHA_256");
		}
	}

	/**
	 * Package-visible for the same reason as {@link #validateSigningKey}. The curve
	 * is checked against the JCA's own P-256 parameters rather than trusted from
	 * {@code keySpec}: the SPKI is what gets persisted and what every certificate
	 * this CA issues carries, so a response whose declared spec and actual key
	 * disagree must not be the one that wins.
	 */
	static ECPublicKey decodeP256PublicKey(byte[] spki, String keyArn) {
		ECPublicKey publicKey;
		try {
			publicKey = (ECPublicKey) KeyFactory.getInstance("EC").generatePublic(new X509EncodedKeySpec(spki));
		} catch (GeneralSecurityException | ClassCastException e) {
			throw new IllegalStateException("KMS key '" + keyArn + "' did not return a usable EC public key", e);
		}
		if (!isP256(publicKey.getParams())) {
			throw new IllegalStateException("KMS key '" + keyArn + "' public key is not on the P-256 curve");
		}
		return publicKey;
	}

	private static boolean isP256(ECParameterSpec params) {
		ECParameterSpec p256 = P256.SPEC;
		return p256.getCurve().equals(params.getCurve()) && p256.getOrder().equals(params.getOrder())
				&& p256.getGenerator().equals(params.getGenerator()) && p256.getCofactor() == params.getCofactor();
	}

	private static KmsClient buildClient(AwsKmsProperties properties, DefaultCredentialsProvider credentialsProvider,
			SdkHttpClient httpClient) {
		KmsClientBuilder builder = KmsClient.builder().region(Region.of(properties.getRegion()))
				.credentialsProvider(credentialsProvider).httpClient(httpClient)
				// The HTTP client's own timeouts bound a stalled connect or a silent
				// socket; neither bounds a response that trickles bytes forever, which
				// is why the API-call bound is set as well.
				.overrideConfiguration(override -> override.apiCallTimeout(properties.getTimeout())
						.apiCallAttemptTimeout(properties.getTimeout()));
		String endpointOverride = properties.getEndpointOverride();
		if (endpointOverride != null && !endpointOverride.isBlank()) {
			builder.endpointOverride(URI.create(endpointOverride));
		}
		return builder.build();
	}

	@PreDestroy
	@Override
	public void close() {
		kms.close();
		httpClient.close();
		credentialsProvider.close();
	}

	/** Held apart so the JCA lookup happens once, on first use rather than boot. */
	private static final class P256 {
		private static final ECParameterSpec SPEC = load();

		private static ECParameterSpec load() {
			try {
				AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC");
				parameters.init(new ECGenParameterSpec("secp256r1"));
				return parameters.getParameterSpec(ECParameterSpec.class);
			} catch (GeneralSecurityException e) {
				throw new IllegalStateException("the JCA provider does not know the P-256 curve", e);
			}
		}
	}
}
