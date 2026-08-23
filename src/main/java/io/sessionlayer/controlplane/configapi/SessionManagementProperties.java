package io.sessionlayer.controlplane.configapi;

import java.time.Duration;
import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "sessionlayer.session")
public class SessionManagementProperties {

	private Duration terminateLockTtl = Duration.ofMinutes(5);

	public Duration getTerminateLockTtl() {
		return terminateLockTtl;
	}

	public void setTerminateLockTtl(Duration terminateLockTtl) {
		this.terminateLockTtl = terminateLockTtl;
	}
}
