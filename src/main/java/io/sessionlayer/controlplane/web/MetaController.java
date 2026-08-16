package io.sessionlayer.controlplane.web;

import io.sessionlayer.controlplane.api.MetaApi;
import io.sessionlayer.controlplane.api.model.HealthStatus;
import io.sessionlayer.controlplane.api.model.ProtocolRanges;
import io.sessionlayer.controlplane.api.model.ProtocolVersionRange;
import io.sessionlayer.controlplane.api.model.VersionInfo;
import io.sessionlayer.controlplane.config.ComponentDescriptor;
import io.sessionlayer.controlplane.protocol.ProtocolVersions;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

@RestController
public class MetaController implements MetaApi {

	private final ComponentDescriptor descriptor;

	public MetaController(ComponentDescriptor descriptor) {
		this.descriptor = descriptor;
	}

	@Override
	public Mono<ResponseEntity<HealthStatus>> getHealth(final ServerWebExchange exchange) {
		// Liveness: if this handler runs, the process is serving requests. The detailed
		// readiness
		// check (DB reachability via R2DBC) lives behind /actuator/health, which also
		// must not leak
		// identity/node/policy detail (management.endpoint.health.show-details=never).
		return Mono.just(ResponseEntity.ok(new HealthStatus(HealthStatus.StatusEnum.PASS)));
	}

	@Override
	public Mono<ResponseEntity<VersionInfo>> getVersion(final ServerWebExchange exchange) {
		ProtocolVersionRange cpGatewayRange = new ProtocolVersionRange(
				ProtocolVersions.display(ProtocolVersions.SUPPORTED_MIN),
				ProtocolVersions.display(ProtocolVersions.SUPPORTED_MAX));
		String wire = ProtocolVersions.display(ProtocolVersions.of(1, 0));
		ProtocolVersionRange agentGatewayRange = new ProtocolVersionRange(wire, wire);
		ProtocolRanges protocols = new ProtocolRanges(cpGatewayRange, agentGatewayRange);
		VersionInfo info = new VersionInfo(descriptor.name(), descriptor.version(), protocols);
		return Mono.just(ResponseEntity.ok(info));
	}
}
