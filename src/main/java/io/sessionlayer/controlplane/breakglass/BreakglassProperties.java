package io.sessionlayer.controlplane.breakglass;

import java.time.Duration;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Properties for the break-glass access model (sessionlayer.breakglass.*).
 * Configures grant TTL, token TTL, offline code defaults, and review SLA.
 */
@ConfigurationProperties(prefix = "sessionlayer.breakglass")
public class BreakglassProperties {

	private Duration grantTtl = Duration.ofHours(1);

	private Duration tokenTtl = Duration.ofMinutes(2);

	private int offlineCodeCount = 10;

	private Duration offlineCodeTtl = Duration.ofDays(90);

	private int offlineCodeEntropyBytes = 16;

	private Duration reviewSla = Duration.ofHours(72);

	public Duration getGrantTtl() {
		return grantTtl;
	}

	public void setGrantTtl(Duration grantTtl) {
		this.grantTtl = grantTtl;
	}

	public Duration getTokenTtl() {
		return tokenTtl;
	}

	public void setTokenTtl(Duration tokenTtl) {
		this.tokenTtl = tokenTtl;
	}

	public int getOfflineCodeCount() {
		return offlineCodeCount;
	}

	public void setOfflineCodeCount(int offlineCodeCount) {
		this.offlineCodeCount = offlineCodeCount;
	}

	public Duration getOfflineCodeTtl() {
		return offlineCodeTtl;
	}

	public void setOfflineCodeTtl(Duration offlineCodeTtl) {
		this.offlineCodeTtl = offlineCodeTtl;
	}

	public int getOfflineCodeEntropyBytes() {
		return offlineCodeEntropyBytes;
	}

	public void setOfflineCodeEntropyBytes(int offlineCodeEntropyBytes) {
		this.offlineCodeEntropyBytes = offlineCodeEntropyBytes;
	}

	public Duration getReviewSla() {
		return reviewSla;
	}

	public void setReviewSla(Duration reviewSla) {
		this.reviewSla = reviewSla;
	}
}
