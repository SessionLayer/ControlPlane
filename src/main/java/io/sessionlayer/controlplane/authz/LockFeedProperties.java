package io.sessionlayer.controlplane.authz;

import java.time.Duration;
import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "sessionlayer.locks")
public class LockFeedProperties {

	private Duration heartbeatInterval = Duration.ofSeconds(10);

	private int streamBufferCapacity = 512;

	public Duration getHeartbeatInterval() {
		return heartbeatInterval;
	}

	public void setHeartbeatInterval(Duration heartbeatInterval) {
		this.heartbeatInterval = heartbeatInterval;
	}

	public int getStreamBufferCapacity() {
		return streamBufferCapacity;
	}

	public void setStreamBufferCapacity(int streamBufferCapacity) {
		this.streamBufferCapacity = streamBufferCapacity;
	}
}
