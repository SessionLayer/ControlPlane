package io.sessionlayer.controlplane.configapi;

import java.time.Duration;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * terminateLockTtl: long enough for a briefly-disconnected Gateway to tear down
 * the session, short enough for the identity to reconnect afterwards.
 */
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
