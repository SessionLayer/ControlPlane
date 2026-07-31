package io.sessionlayer.controlplane.security;

import io.sessionlayer.controlplane.authz.Cidrs;
import java.util.List;
import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "sessionlayer.rest-security")
public class SecurityProperties {

	private final BasicAuth basicAuth = new BasicAuth();

	public BasicAuth getBasicAuth() {
		return basicAuth;
	}

	public static class BasicAuth {
		private boolean enabled = false;
		private List<String> allowedCidrs = List.of();
		private String username;
		private String passwordHash;

		public boolean isEnabled() {
			return enabled;
		}

		public void setEnabled(boolean enabled) {
			this.enabled = enabled;
		}

		public List<String> getAllowedCidrs() {
			return allowedCidrs;
		}

		public void setAllowedCidrs(List<String> allowedCidrs) {
			this.allowedCidrs = allowedCidrs;
		}

		public String getUsername() {
			return username;
		}

		public void setUsername(String username) {
			this.username = username;
		}

		public String getPasswordHash() {
			return passwordHash;
		}

		public void setPasswordHash(String passwordHash) {
			this.passwordHash = passwordHash;
		}

		/**
		 * The gate denies a CIDR it cannot parse rather than raising, so a typo would
		 * otherwise be indistinguishable from a correct non-match — on the one path an
		 * operator walks holding no other credential. Refuse to start instead, naming
		 * the entry. Only when enabled: a stale entry under a disabled hatch must not
		 * take the Control Plane down over a feature nobody asked for.
		 *
		 * <p>
		 * Both families are probed because a v4 probe short-circuits on a family
		 * mismatch and so never range-checks an IPv6 prefix.
		 */
		void validateIfEnabled() {
			if (!enabled) {
				return;
			}
			if (allowedCidrs.isEmpty()) {
				throw new IllegalStateException("sessionlayer.rest-security.basic-auth is enabled with no"
						+ " allowed-cidrs, so it could never authenticate anyone");
			}
			for (String cidr : allowedCidrs) {
				try {
					Cidrs.contains(cidr, "127.0.0.1");
					Cidrs.contains(cidr, "::1");
				} catch (RuntimeException unusable) {
					throw new IllegalStateException("sessionlayer.rest-security.basic-auth.allowed-cidrs entry '" + cidr
							+ "' is unusable: " + unusable.getMessage());
				}
			}
		}
	}
}
