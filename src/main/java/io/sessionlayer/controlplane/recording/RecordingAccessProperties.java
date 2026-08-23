package io.sessionlayer.controlplane.recording;

import java.time.Duration;
import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "sessionlayer.recording")
public class RecordingAccessProperties {

	private Duration signedUrlTtl = Duration.ofMinutes(5);

	public Duration getSignedUrlTtl() {
		return signedUrlTtl;
	}

	public void setSignedUrlTtl(Duration signedUrlTtl) {
		this.signedUrlTtl = signedUrlTtl;
	}
}
