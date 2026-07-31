package io.sessionlayer.controlplane.mtls;

import org.springframework.boot.health.contributor.Health;
import org.springframework.boot.health.contributor.HealthIndicator;
import org.springframework.stereotype.Component;

@Component
public class GrpcMtlsServerHealthIndicator implements HealthIndicator {

	private final GrpcMtlsServer server;
	private final MtlsProperties properties;

	public GrpcMtlsServerHealthIndicator(GrpcMtlsServer server, MtlsProperties properties) {
		this.server = server;
		this.properties = properties;
	}

	@Override
	public Health health() {
		if (!properties.getServer().isEnabled()) {
			return Health.up().withDetail("grpcMtls", "disabled").build();
		}
		return server.isRunning()
				? Health.up().withDetail("grpcMtls", "listening").build()
				: Health.outOfService().withDetail("grpcMtls", "not listening").build();
	}
}
