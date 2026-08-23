package io.sessionlayer.controlplane.web;

import io.sessionlayer.controlplane.api.GatewaysApi;
import io.sessionlayer.controlplane.api.model.GatewayPage;
import io.sessionlayer.controlplane.api.model.GatewayResource;
import io.sessionlayer.controlplane.gateway.GatewayDirectoryService;
import io.sessionlayer.controlplane.gateway.GatewayDirectoryService.GatewayView;
import io.sessionlayer.controlplane.platform.PlatformPermissions;
import java.util.UUID;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

@RestController
public class GatewayController implements GatewaysApi {

	private final GatewayDirectoryService gateways;
	private final PlatformAccess access;

	public GatewayController(GatewayDirectoryService gateways, PlatformAccess access) {
		this.gateways = gateways;
		this.access = access;
	}

	// Gateway names, certificate digests and which Gateway fronts which nodes are
	// fleet-targeting metadata, so the read sits behind the Gateway-admin verb
	// rather than the wider rbac:read - the same reasoning that gates listNodes on
	// node:enroll.
	@Override
	public Mono<ResponseEntity<GatewayPage>> listGateways(String cursor, Integer limit, String name, String status,
			ServerWebExchange exchange) {
		return access.withPermission(PlatformPermissions.GATEWAY_ENROLL,
				subject -> gateways.list(cursor, limit, name, status)
						.map(page -> ResponseEntity
								.ok(new GatewayPage(page.items().stream().map(GatewayController::toResource).toList())
										.nextCursor(page.nextCursor()))));
	}

	@Override
	public Mono<ResponseEntity<GatewayResource>> getGateway(UUID gatewayId, ServerWebExchange exchange) {
		return access.withPermission(PlatformPermissions.GATEWAY_ENROLL,
				subject -> gateways.get(gatewayId).map(gateway -> ResponseEntity.ok(toResource(gateway))));
	}

	@Override
	public Mono<ResponseEntity<Void>> removeGateway(UUID gatewayId, Boolean force, ServerWebExchange exchange) {
		// Deliberately NOT gateway:enroll - a credential trusted to bring a Gateway up
		// is not thereby trusted to take one down (mirrors node:enroll vs node:remove).
		return access.withPermission(PlatformPermissions.GATEWAY_REMOVE,
				subject -> gateways.remove(gatewayId, Boolean.TRUE.equals(force), subject.identity())
						.thenReturn(ResponseEntity.noContent().<Void>build()));
	}

	private static GatewayResource toResource(GatewayView gateway) {
		GatewayResource resource = new GatewayResource(gateway.id(), gateway.name(), gateway.generation(),
				GatewayResource.JoinMethodEnum.fromValue(gateway.joinMethod()),
				GatewayResource.StatusEnum.fromValue(gateway.status()), gateway.presenceNodeCount());
		resource.setFingerprintSha256(gateway.fingerprint());
		// Null at generation 0, and the setter must be handed that null rather than an
		// empty string: the model omits null, and "" would read as a real digest that
		// matches nothing - reintroducing the ambiguity this field removes.
		resource.setPrevFingerprintSha256(gateway.prevFingerprint());
		resource.setIssuedAt(ApiConversions.toOffset(gateway.issuedAt()));
		resource.setNotAfter(ApiConversions.toOffset(gateway.notAfter()));
		resource.setPresenceLastSeenAt(ApiConversions.toOffset(gateway.presenceLastSeenAt()));
		resource.setCreatedAt(ApiConversions.toOffset(gateway.createdAt()));
		resource.setUpdatedAt(ApiConversions.toOffset(gateway.updatedAt()));
		return resource;
	}
}
