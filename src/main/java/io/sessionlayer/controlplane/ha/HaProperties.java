package io.sessionlayer.controlplane.ha;

import java.time.Duration;
import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "sessionlayer.ha")
public class HaProperties {

	private Duration presenceStaleness = Duration.ofSeconds(30);

	public Duration getPresenceStaleness() {
		return presenceStaleness;
	}

	public void setPresenceStaleness(Duration presenceStaleness) {
		this.presenceStaleness = presenceStaleness;
	}
}
