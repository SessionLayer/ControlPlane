package io.sessionlayer.controlplane.web;

import io.sessionlayer.controlplane.api.NodesApi;
import io.sessionlayer.controlplane.api.model.NodeList;
import io.sessionlayer.controlplane.api.model.NodeResource;
import io.sessionlayer.controlplane.api.model.QuarantineNodeRequest;
import io.sessionlayer.controlplane.api.model.RegisterNodeRequest;
import io.sessionlayer.controlplane.node.NodeLifecycleProperties;
import io.sessionlayer.controlplane.node.NodeLifecycleService;
import io.sessionlayer.controlplane.node.NodeRequestException;
import io.sessionlayer.controlplane.node.NodeView;
import io.sessionlayer.controlplane.node.NodeViewService;
import io.sessionlayer.controlplane.platform.PlatformAuthorization;
import io.sessionlayer.controlplane.platform.PlatformPermissions;
import io.sessionlayer.controlplane.platform.PlatformSubject;
import io.sessionlayer.controlplane.security.CurrentAuthentication;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.Map;
import java.util.UUID;
import java.util.function.Function;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.node.ObjectNode;

/**
 * Node lifecycle (RBAC + audited). Registration is a pure API operation.
 */
@RestController
public class NodeController implements NodesApi {

	private final NodeLifecycleService nodeLifecycle;
	private final NodeViewService nodeViews;
	private final NodeLifecycleProperties properties;
	private final PlatformAuthorization platformAuthorization;
	private final CurrentAuthentication currentAuthentication;
	private final ObjectMapper objectMapper;

	public NodeController(NodeLifecycleService nodeLifecycle, NodeViewService nodeViews,
			NodeLifecycleProperties properties, PlatformAuthorization platformAuthorization,
			CurrentAuthentication currentAuthentication, ObjectMapper objectMapper) {
		this.nodeLifecycle = nodeLifecycle;
		this.nodeViews = nodeViews;
		this.properties = properties;
		this.platformAuthorization = platformAuthorization;
		this.currentAuthentication = currentAuthentication;
		this.objectMapper = objectMapper;
	}

	@Override
	public Mono<ResponseEntity<NodeResource>> registerNode(Mono<RegisterNodeRequest> registerNodeRequest,
			ServerWebExchange exchange) {
		return registerNodeRequest.flatMap(req -> withPermission(PlatformPermissions.NODE_ENROLL,
				subject -> nodeLifecycle
						.register(req.getName(), connectorKind(req), req.getAddress(), toLabels(req.getLabels()),
								req.getHostCertificate(), req.getPinnedHostKey(), req.getNodePolicyName(),
								properties.isEnrollmentApprovalRequired(), subject.identity())
						.flatMap(nodeViews::of)
						.map(view -> ResponseEntity.status(HttpStatus.CREATED).body(toResource(view)))));
	}

	@Override
	public Mono<ResponseEntity<NodeList>> listNodes(ServerWebExchange exchange) {
		return withPermission(PlatformPermissions.NODE_ENROLL,
				subject -> nodeLifecycle.list(false).collectList().flatMapMany(nodeViews::ofAll)
						.map(NodeController::toResource).collectList()
						.map(nodes -> ResponseEntity.ok(new NodeList(nodes))));
	}

	@Override
	public Mono<ResponseEntity<NodeResource>> getNode(UUID nodeId, ServerWebExchange exchange) {
		return withPermission(PlatformPermissions.NODE_ENROLL,
				subject -> nodeLifecycle.get(nodeId).flatMap(nodeViews::of)
						.map(view -> ResponseEntity.ok(toResource(view))).switchIfEmpty(Mono.error(notFound(nodeId))));
	}

	@Override
	public Mono<ResponseEntity<NodeResource>> quarantineNode(UUID nodeId,
			Mono<QuarantineNodeRequest> quarantineNodeRequest, ServerWebExchange exchange) {
		return quarantineNodeRequest.flatMap(req -> withPermission(PlatformPermissions.NODE_QUARANTINE,
				subject -> nodeLifecycle
						.quarantine(nodeId, req.getReason(), existingSessions(req), req.getTtlSeconds(),
								subject.identity())
						.flatMap(nodeViews::of).map(view -> ResponseEntity.ok(toResource(view)))));
	}

	@Override
	public Mono<ResponseEntity<NodeResource>> releaseQuarantine(UUID nodeId, ServerWebExchange exchange) {
		return withPermission(PlatformPermissions.NODE_QUARANTINE,
				subject -> nodeLifecycle.releaseQuarantine(nodeId, subject.identity()).flatMap(nodeViews::of)
						.map(view -> ResponseEntity.ok(toResource(view))));
	}

	@Override
	public Mono<ResponseEntity<Void>> removeNode(UUID nodeId, ServerWebExchange exchange) {
		return withPermission(PlatformPermissions.NODE_REMOVE, subject -> nodeLifecycle
				.remove(nodeId, subject.identity()).then(Mono.just(ResponseEntity.noContent().<Void>build())));
	}

	private <T> Mono<ResponseEntity<T>> withPermission(String permission,
			Function<PlatformSubject, Mono<ResponseEntity<T>>> action) {
		return currentAuthentication.subject()
				.flatMap(subject -> platformAuthorization.authorize(subject, permission, null)
						.flatMap(decision -> decision.allowed()
								? action.apply(subject)
								: Mono.just(ResponseEntity.status(HttpStatus.FORBIDDEN).<T>build())))
				.switchIfEmpty(Mono.just(ResponseEntity.status(HttpStatus.FORBIDDEN).build()));
	}

	private static String connectorKind(RegisterNodeRequest req) {
		return req.getConnectorKind() == null ? null : req.getConnectorKind().getValue();
	}

	private static String existingSessions(QuarantineNodeRequest req) {
		return req.getExistingSessions() == null ? null : req.getExistingSessions().getValue();
	}

	private JsonNode toLabels(Map<String, String> labels) {
		ObjectNode node = objectMapper.createObjectNode();
		if (labels != null) {
			labels.forEach(node::put);
		}
		return node;
	}

	private static NodeResource toResource(NodeView view) {
		var node = view.node();
		NodeResource resource = new NodeResource(node.id(), node.name(),
				NodeResource.ConnectorKindEnum.fromValue(node.connectorKind()),
				NodeResource.StatusEnum.fromValue(node.status()), NodeResource.HealthEnum.fromValue(view.health()));
		resource.setAddress(node.address());
		resource.setLabels(labelsMap(node.resolvedLabels()));
		resource.setOwningGateway(view.owningGateway());
		resource.setStatusReason(node.statusReason());
		resource.setStatusChangedBy(node.statusChangedBy());
		resource.setStatusChangedAt(toOffset(node.statusChangedAt()));
		resource.setCreatedAt(toOffset(node.createdAt()));
		resource.setUpdatedAt(toOffset(node.updatedAt()));
		return resource;
	}

	private static Map<String, String> labelsMap(JsonNode labels) {
		Map<String, String> map = new java.util.LinkedHashMap<>();
		if (labels != null && labels.isObject()) {
			for (var entry : labels.properties()) {
				map.put(entry.getKey(), entry.getValue().asString());
			}
		}
		return map;
	}

	private static OffsetDateTime toOffset(Instant instant) {
		return instant == null ? null : instant.atOffset(ZoneOffset.UTC);
	}

	private static NodeRequestException notFound(UUID nodeId) {
		return new NodeRequestException(NodeRequestException.Reason.NOT_FOUND, "node " + nodeId + " not found");
	}
}
