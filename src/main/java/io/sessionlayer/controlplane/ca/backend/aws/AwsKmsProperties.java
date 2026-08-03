package io.sessionlayer.controlplane.ca.backend.aws;

import jakarta.annotation.PostConstruct;
import java.net.URI;
import java.net.URISyntaxException;
import java.time.Duration;
import java.util.regex.Pattern;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * AWS KMS CA backend configuration ({@code sessionlayer.ca.aws.*}). Disabled by
 * default: an unconfigured deployment keeps every {@code aws_kms} CA refused by
 * {@link AwsKmsSignerFactory}'s absence, never silently local.
 *
 * <p>
 * There is no credential property. The SDK's {@code DefaultCredentialsProvider}
 * already spans every deployment shape this platform runs in (IRSA, instance
 * profile, environment, shared profile), so a selector here could only narrow
 * it. No credential, token, secret or key material belongs in this
 * configuration.
 */
@ConfigurationProperties(prefix = "sessionlayer.ca.aws")
public class AwsKmsProperties {

	private static final Pattern REGION = Pattern.compile("[a-z0-9-]+");

	private static final Pattern ACCOUNT_ID = Pattern.compile("[0-9]{12}");

	private static final Pattern PARTITION = Pattern.compile("aws|aws-us-gov|aws-cn");

	private boolean enabled = false;

	private String region;

	private String accountId;

	private String partition = "aws";

	private String endpointOverride;

	private boolean allowInsecureEndpoint = false;

	private Duration timeout = Duration.ofSeconds(10);

	public boolean isEnabled() {
		return enabled;
	}

	public void setEnabled(boolean enabled) {
		this.enabled = enabled;
	}

	public String getRegion() {
		return region;
	}

	public void setRegion(String region) {
		this.region = region;
	}

	public String getAccountId() {
		return accountId;
	}

	public void setAccountId(String accountId) {
		this.accountId = accountId;
	}

	public String getPartition() {
		return partition;
	}

	public void setPartition(String partition) {
		this.partition = partition;
	}

	public String getEndpointOverride() {
		return endpointOverride;
	}

	public void setEndpointOverride(String endpointOverride) {
		this.endpointOverride = endpointOverride;
	}

	public boolean isAllowInsecureEndpoint() {
		return allowInsecureEndpoint;
	}

	public void setAllowInsecureEndpoint(boolean allowInsecureEndpoint) {
		this.allowInsecureEndpoint = allowInsecureEndpoint;
	}

	public Duration getTimeout() {
		return timeout;
	}

	public void setTimeout(Duration timeout) {
		this.timeout = timeout;
	}

	/**
	 * Fails the application context when enabled with a configuration that cannot
	 * anchor a key ARN: a missing or malformed region, account or partition would
	 * otherwise surface only at the first sign attempt, mid-certificate-issuance.
	 * Pure string validation — no network or database access, so this cannot become
	 * a blocking {@code ApplicationReadyEvent} listener that crash-loops startup.
	 */
	@PostConstruct
	void validate() {
		if (!enabled) {
			return;
		}
		requireShape(region, REGION, "region");
		requireShape(accountId, ACCOUNT_ID, "account-id");
		requireShape(partition, PARTITION, "partition");
		validateEndpointOverride();
	}

	private static void requireShape(String value, Pattern shape, String property) {
		String name = "sessionlayer.ca.aws." + property;
		if (value == null || value.isBlank()) {
			throw new IllegalStateException(name + " is required when sessionlayer.ca.aws.enabled=true");
		}
		if (!shape.matcher(value).matches()) {
			throw new IllegalStateException(name + " '" + value + "' is not a valid " + property);
		}
	}

	/**
	 * An endpoint override redirects every KMS call this Control Plane makes, so a
	 * plaintext one is a downgrade of the whole CA seam, not a local convenience.
	 * It takes the same explicit opt-in as a dev KEK, and for the same reason:
	 * a test deployment's shortcut must not be reachable by forgetting a scheme.
	 */
	private void validateEndpointOverride() {
		if (endpointOverride == null || endpointOverride.isBlank()) {
			return;
		}
		URI uri;
		try {
			uri = new URI(endpointOverride);
		} catch (URISyntaxException e) {
			throw new IllegalStateException(
					"sessionlayer.ca.aws.endpoint-override '" + endpointOverride + "' is not a valid URI", e);
		}
		if (!uri.isAbsolute() || uri.getHost() == null || uri.getHost().isBlank()) {
			throw new IllegalStateException("sessionlayer.ca.aws.endpoint-override '" + endpointOverride
					+ "' must be an absolute URL with a host");
		}
		if ("https".equalsIgnoreCase(uri.getScheme())) {
			return;
		}
		if (!"http".equalsIgnoreCase(uri.getScheme()) || !allowInsecureEndpoint) {
			throw new IllegalStateException("sessionlayer.ca.aws.endpoint-override '" + endpointOverride
					+ "' must use https unless sessionlayer.ca.aws.allow-insecure-endpoint=true (dev/test only)");
		}
	}
}
