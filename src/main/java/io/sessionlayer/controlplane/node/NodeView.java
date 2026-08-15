package io.sessionlayer.controlplane.node;

import io.sessionlayer.controlplane.data.runtime.Node;

/**
 * A node as the API answers it: the stored row plus the two values derived at
 * read time from {@code runtime.presence} and {@code runtime.node_host_key}.
 */
public record NodeView(Node node, String health, String owningGateway) {

	public static final String HEALTH_UNKNOWN = "unknown";
	public static final String HEALTH_HEALTHY = "healthy";
	public static final String HEALTH_UNHEALTHY = "unhealthy";
	public static final String HEALTH_UNREACHABLE = "unreachable";
}
