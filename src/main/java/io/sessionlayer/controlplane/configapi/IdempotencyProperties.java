package io.sessionlayer.controlplane.configapi;

import java.time.Duration;
import org.springframework.boot.context.properties.ConfigurationProperties;

/** TTL determines the replay window; expired keys re-execute. */
@ConfigurationProperties(prefix = "sessionlayer.idempotency")
public class IdempotencyProperties {

	private Duration ttl = Duration.ofHours(24);

	public Duration getTtl() {
		return ttl;
	}

	public void setTtl(Duration ttl) {
		this.ttl = ttl;
	}
}
