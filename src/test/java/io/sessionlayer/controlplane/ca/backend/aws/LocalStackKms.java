package io.sessionlayer.controlplane.ca.backend.aws;

import java.net.URI;
import java.util.UUID;
import org.testcontainers.localstack.LocalStackContainer;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.model.CreateKeyRequest;
import software.amazon.awssdk.services.kms.model.KeySpec;
import software.amazon.awssdk.services.kms.model.KeyUsageType;

/**
 * The local KMS the {@code aws_kms} integration tests run against. LocalStack's
 * KMS generates real asymmetric keys and produces real ECDSA signatures over
 * the real AWS protocol, so those tests exercise the genuine SDK path - SigV4
 * request signing, endpoint resolution, the credential chain, DER response
 * handling - rather than a double of the {@link KmsSigner} seam.
 *
 * <p>
 * Three fidelity gaps matter when reading a test that works around one. The
 * community edition evaluates no IAM policy, so a request carrying invalid
 * credentials is served exactly as a valid one is and a rejected credential
 * cannot originate here. Its {@code GetPublicKey} answers for a disabled key,
 * where AWS raises {@code DisabledException}. And it signs a P-384 key under
 * {@code ECDSA_SHA_256} and reports the result as {@code ECDSA_SHA_256}, where
 * AWS accepts only an algorithm the key's own {@code SigningAlgorithms} lists.
 * Everything the tests do rely on matches AWS: a DER {@code SEQUENCE} from
 * {@code Sign}, the full key ARN echoed as {@code KeyId} by both {@code Sign}
 * and {@code GetPublicKey}, {@code DisabledException} for a disabled key,
 * {@code KMSInvalidStateException} for one pending deletion, and alias
 * resolution.
 */
public final class LocalStackKms {

	/** Every ARN LocalStack issues is under this account. */
	public static final String ACCOUNT_ID = "000000000000";

	@SuppressWarnings("resource")
	private static final LocalStackContainer CONTAINER = new LocalStackContainer("localstack/localstack:4")
			.withServices("kms")
			// Left to itself LocalStack resolves api.localstack.cloud and starts its own
			// DNS server during boot. On a host that cannot reach either, readiness goes
			// from seconds to minutes and presents as a hung container rather than as a
			// name-resolution failure.
			.withEnv("DNS_ADDRESS", "0").withEnv("SKIP_SSL_CERT_DOWNLOAD", "1").withEnv("DISABLE_EVENTS", "1");

	private static final KmsClient ADMIN;

	static {
		CONTAINER.start();
		// AwsKmsSignerFactory builds a DefaultCredentialsProvider and exposes no seam
		// for credentials, deliberately. System properties are that chain's first
		// link, so this is how the container's credentials reach the production
		// factory: through the real chain rather than around it.
		System.setProperty("aws.accessKeyId", CONTAINER.getAccessKey());
		System.setProperty("aws.secretAccessKey", CONTAINER.getSecretKey());
		ADMIN = KmsClient.builder().region(Region.of(CONTAINER.getRegion())).endpointOverride(CONTAINER.getEndpoint())
				.credentialsProvider(StaticCredentialsProvider
						.create(AwsBasicCredentials.create(CONTAINER.getAccessKey(), CONTAINER.getSecretKey())))
				.build();
	}

	private LocalStackKms() {
	}

	public static URI endpoint() {
		return CONTAINER.getEndpoint();
	}

	public static String region() {
		return CONTAINER.getRegion();
	}

	/**
	 * Key administration - {@code CreateKey}, {@code DisableKey},
	 * {@code CreateAlias} - which is fixture setup, not a path the Control Plane
	 * has or wants: its documented IAM surface is {@code kms:Sign} plus
	 * {@code kms:GetPublicKey} on one key.
	 */
	public static KmsClient admin() {
		return ADMIN;
	}

	public static String createSigningKey() {
		return createKey(KeySpec.ECC_NIST_P256);
	}

	public static String createKey(KeySpec keySpec) {
		return ADMIN.createKey(CreateKeyRequest.builder().keySpec(keySpec).keyUsage(KeyUsageType.SIGN_VERIFY).build())
				.keyMetadata().arn();
	}

	public static void disable(String keyArn) {
		ADMIN.disableKey(request -> request.keyId(keyArn));
	}

	public static void scheduleDeletion(String keyArn) {
		ADMIN.scheduleKeyDeletion(request -> request.keyId(keyArn).pendingWindowInDays(7));
	}

	public static String createAlias(String keyArn) {
		String alias = "alias/session-ca-" + UUID.randomUUID();
		ADMIN.createAlias(request -> request.aliasName(alias).targetKeyId(keyArn));
		return alias;
	}

	public static AwsKmsProperties properties() {
		return propertiesFor(endpoint().toString());
	}

	public static AwsKmsProperties propertiesFor(String endpointOverride) {
		AwsKmsProperties properties = new AwsKmsProperties();
		properties.setEnabled(true);
		properties.setRegion(region());
		properties.setAccountId(ACCOUNT_ID);
		properties.setEndpointOverride(endpointOverride);
		properties.setAllowEndpointOverride(true);
		properties.setAllowInsecureEndpoint(true);
		properties.validate();
		return properties;
	}
}
