package io.sessionlayer.controlplane.web;

import java.time.Duration;
import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "sessionlayer.audit.search")
public class AuditSearchProperties {

	private Duration defaultWindow = Duration.ofDays(90);
	private Duration maxWindow = Duration.ofDays(366);

	public Duration getDefaultWindow() {
		return defaultWindow;
	}

	public void setDefaultWindow(Duration defaultWindow) {
		this.defaultWindow = defaultWindow;
	}

	public Duration getMaxWindow() {
		return maxWindow;
	}

	public void setMaxWindow(Duration maxWindow) {
		this.maxWindow = maxWindow;
	}
}
