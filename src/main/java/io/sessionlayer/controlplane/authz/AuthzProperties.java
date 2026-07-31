package io.sessionlayer.controlplane.authz;

import java.time.Duration;
import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "sessionlayer.authz")
public class AuthzProperties {

	private Duration decisionTtl = Duration.ofSeconds(45);

	private Duration maxGrantTtl = Duration.ofHours(1);

	private Duration contextSignerCertTtl = Duration.ofHours(24);

	public Duration getDecisionTtl() {
		return decisionTtl;
	}

	public void setDecisionTtl(Duration decisionTtl) {
		this.decisionTtl = decisionTtl;
	}

	public Duration getMaxGrantTtl() {
		return maxGrantTtl;
	}

	public void setMaxGrantTtl(Duration maxGrantTtl) {
		this.maxGrantTtl = maxGrantTtl;
	}

	public Duration getContextSignerCertTtl() {
		return contextSignerCertTtl;
	}

	public void setContextSignerCertTtl(Duration contextSignerCertTtl) {
		this.contextSignerCertTtl = contextSignerCertTtl;
	}
}
