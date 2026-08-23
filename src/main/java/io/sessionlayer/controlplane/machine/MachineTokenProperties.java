package io.sessionlayer.controlplane.machine;

import java.time.Duration;
import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "sessionlayer.machine")
public class MachineTokenProperties {

	private String issuer = "sessionlayer://cp";

	private String audience = "sessionlayer-cp-api";

	private Duration tokenTtl = Duration.ofMinutes(5);

	private Duration clockSkew = Duration.ofSeconds(30);

	private Duration maxAssertionAge = Duration.ofMinutes(5);

	public String getIssuer() {
		return issuer;
	}

	public void setIssuer(String issuer) {
		this.issuer = issuer;
	}

	public String getAudience() {
		return audience;
	}

	public void setAudience(String audience) {
		this.audience = audience;
	}

	public Duration getTokenTtl() {
		return tokenTtl;
	}

	public void setTokenTtl(Duration tokenTtl) {
		this.tokenTtl = tokenTtl;
	}

	public Duration getClockSkew() {
		return clockSkew;
	}

	public void setClockSkew(Duration clockSkew) {
		this.clockSkew = clockSkew;
	}

	public Duration getMaxAssertionAge() {
		return maxAssertionAge;
	}

	public void setMaxAssertionAge(Duration maxAssertionAge) {
		this.maxAssertionAge = maxAssertionAge;
	}
}
