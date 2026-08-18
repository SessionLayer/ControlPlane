package io.sessionlayer.controlplane.ca.backend.azure;

import jakarta.annotation.PostConstruct;
import java.net.URI;
import java.net.URISyntaxException;
import java.time.Duration;
import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "sessionlayer.ca.azure")
public class AzureKeyVaultProperties {

	/**
	 * Which {@code azure-identity} credential builds the vault's
	 * {@code TokenCredential}. {@code CLIENT_SECRET} is deliberately absent: the
	 * SDK's {@code ClientSecretCredentialBuilder} takes the secret as a builder
	 * argument with no environment-sourced variant, so offering it here would mean
	 * either a secret in this configuration (refused - no credential, token, or key
	 * material belongs in config) or silently duplicating what {@code DEFAULT}
	 * already does via {@code EnvironmentCredential}
	 * (AZURE_CLIENT_ID/AZURE_CLIENT_SECRET/AZURE_TENANT_ID).
	 */
	public enum Credential {
		DEFAULT, MANAGED_IDENTITY, WORKLOAD_IDENTITY
	}

	private boolean enabled = false;

	private String vaultUri;

	private Credential credential = Credential.DEFAULT;

	private String clientId;

	private Duration timeout = Duration.ofSeconds(10);

	public boolean isEnabled() {
		return enabled;
	}

	public void setEnabled(boolean enabled) {
		this.enabled = enabled;
	}

	public String getVaultUri() {
		return vaultUri;
	}

	public void setVaultUri(String vaultUri) {
		this.vaultUri = vaultUri;
	}

	public Credential getCredential() {
		return credential;
	}

	public void setCredential(Credential credential) {
		this.credential = credential;
	}

	public String getClientId() {
		return clientId;
	}

	public void setClientId(String clientId) {
		this.clientId = clientId;
	}

	public Duration getTimeout() {
		return timeout;
	}

	public void setTimeout(Duration timeout) {
		this.timeout = timeout;
	}

	/**
	 * Fails the application context when enabled with an unusable vault-uri: a
	 * missing, unparseable, or non-HTTPS URI would otherwise surface only at the
	 * first sign attempt, mid-certificate-issuance. Pure string validation - no
	 * network or database access, so this cannot become a blocking
	 * {@code ApplicationReadyEvent} listener that crash-loops startup.
	 */
	@PostConstruct
	void validate() {
		if (!enabled) {
			return;
		}
		if (vaultUri == null || vaultUri.isBlank()) {
			throw new IllegalStateException(
					"sessionlayer.ca.azure.vault-uri is required when sessionlayer.ca.azure.enabled=true");
		}
		URI uri;
		try {
			uri = new URI(vaultUri);
		} catch (URISyntaxException e) {
			throw new IllegalStateException("sessionlayer.ca.azure.vault-uri '" + vaultUri + "' is not a valid URI", e);
		}
		if (!uri.isAbsolute() || uri.getHost() == null || uri.getHost().isBlank()) {
			throw new IllegalStateException(
					"sessionlayer.ca.azure.vault-uri '" + vaultUri + "' must be an absolute URL with a host");
		}
		if (!"https".equalsIgnoreCase(uri.getScheme())) {
			throw new IllegalStateException("sessionlayer.ca.azure.vault-uri '" + vaultUri + "' must use https");
		}
	}
}
