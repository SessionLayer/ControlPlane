package io.sessionlayer.controlplane.agent;

import java.time.Duration;
import java.util.List;
import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "sessionlayer.agent-join")
public class AgentJoinProperties {

	private Duration identityCertTtl = Duration.ofHours(24);

	private Duration certBackdate = Duration.ofMinutes(2);

	private Duration joinTokenTtl = Duration.ofMinutes(10);

	private Duration joinTokenMaxTtl = Duration.ofHours(1);

	// Replay window for a completed RenewAgentIdentity response: only needs to
	// outlive a client-side RPC deadline + backoff retry, not a real operational
	// TTL.
	private Duration renewalReceiptTtl = Duration.ofMinutes(5);

	private final Oidc oidc = new Oidc();
	private final Mtls mtls = new Mtls();

	public static class Oidc {

		private boolean enabled = false;
		private String issuer;
		private String jwksUri;
		private String audience;
		private List<String> allowedAlgs = List.of("RS256", "ES256");
		private Duration clockSkew = Duration.ofSeconds(60);
		private String nodeClaim = "sub";

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

		public String getJwksUri() {
			return jwksUri;
		}

		public void setJwksUri(String jwksUri) {
			this.jwksUri = jwksUri;
		}

		public String getAudience() {
			return audience;
		}

		public void setAudience(String audience) {
			this.audience = audience;
		}

		public List<String> getAllowedAlgs() {
			return allowedAlgs;
		}

		public void setAllowedAlgs(List<String> allowedAlgs) {
			this.allowedAlgs = allowedAlgs;
		}

		public Duration getClockSkew() {
			return clockSkew;
		}

		public void setClockSkew(Duration clockSkew) {
			this.clockSkew = clockSkew;
		}

		public String getNodeClaim() {
			return nodeClaim;
		}

		public void setNodeClaim(String nodeClaim) {
			this.nodeClaim = nodeClaim;
		}
	}

	public static class Mtls {

		private boolean enabled = false;
		private String operatorCaPem;

		public boolean isEnabled() {
			return enabled;
		}

		public void setEnabled(boolean enabled) {
			this.enabled = enabled;
		}

		public String getOperatorCaPem() {
			return operatorCaPem;
		}

		public void setOperatorCaPem(String operatorCaPem) {
			this.operatorCaPem = operatorCaPem;
		}
	}

	public Duration getIdentityCertTtl() {
		return identityCertTtl;
	}

	public void setIdentityCertTtl(Duration identityCertTtl) {
		this.identityCertTtl = identityCertTtl;
	}

	public Duration getCertBackdate() {
		return certBackdate;
	}

	public void setCertBackdate(Duration certBackdate) {
		this.certBackdate = certBackdate;
	}

	public Duration getJoinTokenTtl() {
		return joinTokenTtl;
	}

	public void setJoinTokenTtl(Duration joinTokenTtl) {
		this.joinTokenTtl = joinTokenTtl;
	}

	public Duration getJoinTokenMaxTtl() {
		return joinTokenMaxTtl;
	}

	public void setJoinTokenMaxTtl(Duration joinTokenMaxTtl) {
		this.joinTokenMaxTtl = joinTokenMaxTtl;
	}

	public Duration getRenewalReceiptTtl() {
		return renewalReceiptTtl;
	}

	public void setRenewalReceiptTtl(Duration renewalReceiptTtl) {
		this.renewalReceiptTtl = renewalReceiptTtl;
	}

	public Oidc getOidc() {
		return oidc;
	}

	public Mtls getMtls() {
		return mtls;
	}
}
