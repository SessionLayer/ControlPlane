package io.sessionlayer.controlplane.platform;

import java.time.Instant;
import java.util.Map;

public record PlatformScope(Map<String, String> nodeLabels, String user, Instant at) {

	public PlatformScope {
		nodeLabels = (nodeLabels == null) ? Map.of() : Map.copyOf(nodeLabels);
	}
}
