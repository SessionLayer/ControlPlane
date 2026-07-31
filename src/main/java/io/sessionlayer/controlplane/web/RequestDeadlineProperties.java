package io.sessionlayer.controlplane.web;

import java.time.Duration;
import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "sessionlayer.web")
public class RequestDeadlineProperties {

	/**
	 * Bounds every REST request: the gRPC plane already deadlines every RPC via
	 * {@code ReactiveBridge.forward}; a wedged query on this plane (lock
	 * contention, a stalled scan) used to hang the caller's connection forever with
	 * no operator-visible signal. Audit search is cursor-paginated (<=200 rows,
	 * {@code CursorPages.MAX_LIMIT}) and export/replay only issue a presigned URL,
	 * so neither legitimately needs a long budget — default matches
	 * {@code sessionlayer.mtls.rpc-timeout} for one consistent number, overridable
	 * per deployment.
	 */
	private Duration requestTimeout = Duration.ofSeconds(15);

	public Duration getRequestTimeout() {
		return requestTimeout;
	}

	public void setRequestTimeout(Duration requestTimeout) {
		this.requestTimeout = requestTimeout;
	}
}
