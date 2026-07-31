package io.sessionlayer.controlplane.jit;

import java.time.Duration;
import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "sessionlayer.jit")
public class JitProperties {

	private Duration approvalWindow = Duration.ofMinutes(30);

	private Duration maxGrantTtl = Duration.ofHours(8);

	private Duration revokeLockTtl = Duration.ofSeconds(120);

	private Duration lookupTimeout = Duration.ofMillis(150);

	public Duration getApprovalWindow() {
		return approvalWindow;
	}

	public void setApprovalWindow(Duration approvalWindow) {
		this.approvalWindow = approvalWindow;
	}

	public Duration getMaxGrantTtl() {
		return maxGrantTtl;
	}

	public void setMaxGrantTtl(Duration maxGrantTtl) {
		this.maxGrantTtl = maxGrantTtl;
	}

	public Duration getRevokeLockTtl() {
		return revokeLockTtl;
	}

	public void setRevokeLockTtl(Duration revokeLockTtl) {
		this.revokeLockTtl = revokeLockTtl;
	}

	public Duration getLookupTimeout() {
		return lookupTimeout;
	}

	public void setLookupTimeout(Duration lookupTimeout) {
		this.lookupTimeout = lookupTimeout;
	}
}
