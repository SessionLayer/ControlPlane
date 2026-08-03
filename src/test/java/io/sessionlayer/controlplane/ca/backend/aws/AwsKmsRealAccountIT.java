package io.sessionlayer.controlplane.ca.backend.aws;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import io.sessionlayer.controlplane.ca.CaKeyType;
import io.sessionlayer.controlplane.ca.sign.EcdsaSignatures;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.Signature;
import java.security.interfaces.ECPublicKey;
import org.junit.jupiter.api.Test;

/**
 * The same seam against a real AWS account. Nothing here runs unless
 * {@code SESSIONLAYER_AWS_KMS_KEY_ARN} names a key ARN, so an ordinary build
 * skips it; {@link KmsSdkContractIT} is what runs everywhere. What this adds is
 * the two things a local KMS cannot answer: whether AWS's own endpoint
 * resolution, TLS and SigV4 accept the request this Control Plane builds, and
 * whether a genuine KMS signature verifies against the key AWS reports.
 *
 * <pre>
 * export SESSIONLAYER_AWS_KMS_KEY_ARN=arn:aws:kms:eu-west-1:111122223333:key/&lt;key-id&gt;
 * ./mvnw -B -ntp verify -Dit.test=AwsKmsRealAccountIT -Dtest=none -DfailIfNoTests=false
 * </pre>
 *
 * Run it on its own, as above: the LocalStack fixture the other KMS tests share
 * installs its container credentials into this JVM's system properties, which
 * are the first link of the default chain and would shadow the operator's.
 *
 * <p>
 * The key must be {@code ECC_NIST_P256} with {@code SIGN_VERIFY} usage.
 * Credentials come from the SDK's default chain — environment, profile, web
 * identity or instance role, whichever the caller already has. The permissions
 * needed are the two actions this seam ever performs, on the one key:
 *
 * <pre>
 * {
 *   "Version": "2012-10-17",
 *   "Statement": [
 *     {
 *       "Effect": "Allow",
 *       "Action": ["kms:Sign", "kms:GetPublicKey"],
 *       "Resource": "arn:aws:kms:eu-west-1:111122223333:key/&lt;key-id&gt;"
 *     }
 *   ]
 * }
 * </pre>
 *
 * No {@code kms:DescribeKey}, and no wildcard resource: a disabled or
 * pending-deletion key fails closed at the first signature anyway, so widening
 * the required IAM surface to learn it earlier is the wrong trade.
 */
class AwsKmsRealAccountIT {

	private static final String KEY_ARN_ENV = "SESSIONLAYER_AWS_KMS_KEY_ARN";

	/** {@code arn:<partition>:kms:<region>:<account-id>:key/<key-id>}. */
	private static final int PARTITION = 1;
	private static final int REGION = 3;
	private static final int ACCOUNT_ID = 4;

	@Test
	void realKmsResolvesTheKeyAndSignsADigestThatVerifiesAgainstIt() throws Exception {
		String keyArn = System.getenv(KEY_ARN_ENV);
		assumeTrue(keyArn != null && !keyArn.isBlank(), KEY_ARN_ENV + " is not set");

		try (AwsKmsSignerFactory factory = new AwsKmsSignerFactory(propertiesAnchoredOn(keyArn))) {
			KmsKeyArn key = KmsKeyArn.parse(keyArn, factory.anchor());
			ECPublicKey publicKey = factory.fetchPublicKey(key);
			byte[] digest = MessageDigest.getInstance("SHA-256")
					.digest("sessionlayer-real-account".getBytes(StandardCharsets.UTF_8));

			byte[] signature = factory.signerFor(key, publicKey).signDigestDer(digest);

			assertThat(signature[0]).isEqualTo((byte) 0x30);
			assertThat(EcdsaSignatures.fromDer(signature)).isNotNull();
			Signature verifier = Signature.getInstance("NONEwithECDSA");
			verifier.initVerify(publicKey);
			verifier.update(digest);
			assertThat(verifier.verify(signature)).isTrue();
			assertThat(new KmsCaBackend(CaKeyType.ECDSA_NISTP256, factory.signerFor(key, publicKey))
					.sign("real-account-to-be-signed".getBytes(StandardCharsets.UTF_8))).isNotNull();
		}
	}

	/**
	 * A deployment configures the anchor and the key reference independently; an
	 * operator running this supplies one ARN, so the anchor is read back out of it
	 * rather than asked for three more times.
	 */
	private static AwsKmsProperties propertiesAnchoredOn(String keyArn) {
		String[] fields = keyArn.split(":", -1);
		assumeTrue(fields.length == 6, KEY_ARN_ENV + " must be a full KMS key ARN");
		AwsKmsProperties properties = new AwsKmsProperties();
		properties.setEnabled(true);
		properties.setPartition(fields[PARTITION]);
		properties.setRegion(fields[REGION]);
		properties.setAccountId(fields[ACCOUNT_ID]);
		properties.validate();
		return properties;
	}
}
