package io.sessionlayer.controlplane.ca.backend.aws;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;

/**
 * A misconfigured {@code sessionlayer.ca.aws.*} fails the application context
 * at startup, naming the property — never a listener that reaches the database
 * or network, which is how a blocking readiness check crash-loops a whole fleet
 * instead of refusing one bad config value.
 */
class AwsKmsPropertiesTest {

	private final ApplicationContextRunner contextRunner = new ApplicationContextRunner()
			.withUserConfiguration(AwsKmsConfiguration.class);

	private static AwsKmsProperties enabled() {
		AwsKmsProperties properties = new AwsKmsProperties();
		properties.setEnabled(true);
		properties.setRegion("us-east-1");
		properties.setAccountId("111122223333");
		return properties;
	}

	@Test
	void disabledNeedsNoRegionOrAccount() {
		assertThatCode(new AwsKmsProperties()::validate).doesNotThrowAnyException();
	}

	@Test
	void enabledWithARegionAndAccountStarts() {
		assertThatCode(enabled()::validate).doesNotThrowAnyException();
	}

	@Test
	void enabledWithNoRegionRefusesToStart() {
		AwsKmsProperties properties = enabled();
		properties.setRegion(null);

		assertThatThrownBy(properties::validate).isInstanceOf(IllegalStateException.class)
				.hasMessageContaining("sessionlayer.ca.aws.region");
	}

	@Test
	void enabledWithNoAccountIdRefusesToStart() {
		AwsKmsProperties properties = enabled();
		properties.setAccountId(null);

		assertThatThrownBy(properties::validate).isInstanceOf(IllegalStateException.class)
				.hasMessageContaining("sessionlayer.ca.aws.account-id");
	}

	/**
	 * An account id is exactly twelve digits. A shorter or non-numeric one cannot
	 * be the account any real key ARN names, so accepting it would leave the
	 * allow-list anchor comparing against a value that matches nothing — a CA that
	 * can never be adopted, discovered at rotation rather than at boot.
	 */
	@Test
	void enabledWithAMalformedAccountIdRefusesToStart() {
		for (String bad : new String[]{"11112222333", "1111222233334", "  ", "1111-2222-3333"}) {
			AwsKmsProperties properties = enabled();
			properties.setAccountId(bad);

			assertThatThrownBy(properties::validate).as(bad).isInstanceOf(IllegalStateException.class)
					.hasMessageContaining("sessionlayer.ca.aws.account-id");
		}
	}

	@Test
	void enabledWithAMalformedRegionRefusesToStart() {
		AwsKmsProperties properties = enabled();
		properties.setRegion("US-EAST-1");

		assertThatThrownBy(properties::validate).isInstanceOf(IllegalStateException.class)
				.hasMessageContaining("sessionlayer.ca.aws.region");
	}

	@Test
	void enabledWithAnUnknownPartitionRefusesToStart() {
		AwsKmsProperties properties = enabled();
		properties.setPartition("aws-secret");

		assertThatThrownBy(properties::validate).isInstanceOf(IllegalStateException.class)
				.hasMessageContaining("sessionlayer.ca.aws.partition");
	}

	@Test
	void theDefaultPartitionIsCommercialAws() {
		assertThat(new AwsKmsProperties().getPartition()).isEqualTo("aws");
	}

	@Test
	void anHttpsEndpointOverrideIsAccepted() {
		AwsKmsProperties properties = enabled();
		properties.setEndpointOverride("https://kms.example.internal");

		assertThatCode(properties::validate).doesNotThrowAnyException();
	}

	/**
	 * An endpoint override redirects every KMS call this Control Plane makes, so a
	 * plaintext one exposes the digests being signed and lets anything on the path
	 * answer for KMS. It is refused unless the operator says so explicitly.
	 */
	@Test
	void aPlaintextEndpointOverrideRefusesToStartUnlessExplicitlyAllowed() {
		AwsKmsProperties properties = enabled();
		properties.setEndpointOverride("http://localhost:4566");

		assertThatThrownBy(properties::validate).isInstanceOf(IllegalStateException.class)
				.hasMessageContaining("allow-insecure-endpoint");

		properties.setAllowInsecureEndpoint(true);
		assertThatCode(properties::validate).doesNotThrowAnyException();
	}

	/**
	 * The opt-in covers plaintext HTTP and nothing else: a scheme the SDK cannot
	 * speak would otherwise be waved through by the same flag and fail obscurely at
	 * the first call.
	 */
	@Test
	void allowInsecureEndpointDoesNotAdmitAnArbitraryScheme() {
		AwsKmsProperties properties = enabled();
		properties.setAllowInsecureEndpoint(true);
		properties.setEndpointOverride("ftp://kms.example.internal");

		assertThatThrownBy(properties::validate).isInstanceOf(IllegalStateException.class)
				.hasMessageContaining("endpoint-override");
	}

	@Test
	void anEndpointOverrideWithNoHostRefusesToStart() {
		AwsKmsProperties properties = enabled();
		properties.setEndpointOverride("kms.example.internal:443");

		assertThatThrownBy(properties::validate).isInstanceOf(IllegalStateException.class)
				.hasMessageContaining("absolute URL with a host");
	}

	@Test
	void anUnparseableEndpointOverrideRefusesToStart() {
		AwsKmsProperties properties = enabled();
		properties.setEndpointOverride("not a valid uri");

		assertThatThrownBy(properties::validate).isInstanceOf(IllegalStateException.class)
				.hasMessageContaining("sessionlayer.ca.aws.endpoint-override");
	}

	@Test
	void theApplicationContextItselfFailsToStartWithNoRegion() {
		contextRunner.withPropertyValues("sessionlayer.ca.aws.enabled=true",
				"sessionlayer.ca.aws.account-id=111122223333")
				.run(context -> assertThat(context).hasFailed().getFailure().rootCause()
						.isInstanceOf(IllegalStateException.class)
						.hasMessageContaining("sessionlayer.ca.aws.region"));
	}

	@Test
	void theApplicationContextItselfFailsToStartWithAPlaintextEndpointOverride() {
		contextRunner
				.withPropertyValues("sessionlayer.ca.aws.enabled=true", "sessionlayer.ca.aws.region=us-east-1",
						"sessionlayer.ca.aws.account-id=111122223333",
						"sessionlayer.ca.aws.endpoint-override=http://localhost:4566")
				.run(context -> assertThat(context).hasFailed().getFailure().rootCause()
						.isInstanceOf(IllegalStateException.class)
						.hasMessageContaining("allow-insecure-endpoint"));
	}

	@Test
	void theApplicationContextStartsCleanWhenDisabled() {
		contextRunner.run(context -> assertThat(context).hasNotFailed());
	}
}
