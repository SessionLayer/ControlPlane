package io.sessionlayer.controlplane.oidc;

import java.time.Duration;
import java.util.List;
import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "sessionlayer.oidc")
public class OidcProperties {

	private boolean enabled = false;
	private String issuer;
	private String clientId;
	private String clientSecret;
	private String redirectUri;

	private List<String> scopes = List.of("openid", "profile", "email");
	private List<String> algAllowList = List.of("RS256", "ES256");
	private Duration clockSkew = Duration.ofSeconds(60);
	private Duration jwksCacheTtl = Duration.ofMinutes(5);
	private String groupsClaim = "groups";
	private String identityClaim = "email";

	private String stateHmacKey;
	private final Device device = new Device();

	public static class Device {
		private Duration pollInterval = Duration.ofSeconds(5);
		private Duration expiry = Duration.ofMinutes(10);
		private boolean enforceSourceMatch = false;

		public boolean isEnforceSourceMatch() {
			return enforceSourceMatch;
		}

		public void setEnforceSourceMatch(boolean enforceSourceMatch) {
			this.enforceSourceMatch = enforceSourceMatch;
		}

		public Duration getPollInterval() {
			return pollInterval;
		}

		public void setPollInterval(Duration pollInterval) {
			this.pollInterval = pollInterval;
		}

		public Duration getExpiry() {
			return expiry;
		}

		public void setExpiry(Duration expiry) {
			this.expiry = expiry;
		}
	}

	public boolean isEnabled() {
		return enabled;
	}

	public void setEnabled(boolean enabled) {
		this.enabled = enabled;
	}

	public String getIssuer() {
		return issuer;
	}

	public void setIssuer(String issuer) {
		this.issuer = issuer;
	}

	public String getClientId() {
		return clientId;
	}

	public void setClientId(String clientId) {
		this.clientId = clientId;
	}

	public String getClientSecret() {
		return clientSecret;
	}

	public void setClientSecret(String clientSecret) {
		this.clientSecret = clientSecret;
	}

	public String getRedirectUri() {
		return redirectUri;
	}

	public void setRedirectUri(String redirectUri) {
		this.redirectUri = redirectUri;
	}

	/**
	 * Never uses request Host header (phishing risk); derived from redirect-uri.
	 */
	public String verificationBaseUrl() {
		if (redirectUri == null || redirectUri.isBlank()) {
			return "";
		}
		try {
			java.net.URI uri = java.net.URI.create(redirectUri);
			return uri.getScheme() + "://" + uri.getAuthority();
		} catch (RuntimeException malformed) {
			return "";
		}
	}

	public List<String> getScopes() {
		return scopes;
	}

	public void setScopes(List<String> scopes) {
		this.scopes = scopes;
	}

	public List<String> getAlgAllowList() {
		return algAllowList;
	}

	public void setAlgAllowList(List<String> algAllowList) {
		this.algAllowList = algAllowList;
	}

	public Duration getClockSkew() {
		return clockSkew;
	}

	public void setClockSkew(Duration clockSkew) {
		this.clockSkew = clockSkew;
	}

	public Duration getJwksCacheTtl() {
		return jwksCacheTtl;
	}

	public void setJwksCacheTtl(Duration jwksCacheTtl) {
		this.jwksCacheTtl = jwksCacheTtl;
	}

	public String getGroupsClaim() {
		return groupsClaim;
	}

	public void setGroupsClaim(String groupsClaim) {
		this.groupsClaim = groupsClaim;
	}

	public String getIdentityClaim() {
		return identityClaim;
	}

	public void setIdentityClaim(String identityClaim) {
		this.identityClaim = identityClaim;
	}

	public String getStateHmacKey() {
		return stateHmacKey;
	}

	public void setStateHmacKey(String stateHmacKey) {
		this.stateHmacKey = stateHmacKey;
	}

	public Device getDevice() {
		return device;
	}
}
