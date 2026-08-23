package io.sessionlayer.controlplane.web;

import io.sessionlayer.controlplane.api.NodesApi;
import io.sessionlayer.controlplane.api.model.NodeHostAnchor;
import io.sessionlayer.controlplane.api.model.NodeHostAnchors;
import io.sessionlayer.controlplane.api.model.NodeHostAnchorsRequest;
import io.sessionlayer.controlplane.api.model.NodeList;
import io.sessionlayer.controlplane.api.model.NodeResource;
import io.sessionlayer.controlplane.api.model.QuarantineNodeRequest;
import io.sessionlayer.controlplane.api.model.RegisterNodeRequest;
import io.sessionlayer.controlplane.configapi.IdempotencyService;
import io.sessionlayer.controlplane.data.runtime.NodeHostKey;
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
import java.util.List;
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

@RestController
public class NodeController implements NodesApi {

	private final NodeLifecycleService nodeLifecycle;
	private final NodeViewService nodeViews;
	private final NodeLifecycleProperties properties;
	private final PlatformAuthorization platformAuthorization;
	private final CurrentAuthentication currentAuthentication;
	private final IdempotencyService idempotency;
	private final ObjectMapper objectMapper;

	public NodeController(NodeLifecycleService nodeLifecycle, NodeViewService nodeViews,
			NodeLifecycleProperties properties, PlatformAuthorization platformAuthorization,
			CurrentAuthentication currentAuthentication, IdempotencyService idempotency, ObjectMapper objectMapper) {
		this.nodeLifecycle = nodeLifecycle;
		this.nodeViews = nodeViews;
		this.properties = properties;
		this.idempotency = idempotency;
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
	public Mono<ResponseEntity<NodeHostAnchors>> getNodeHostAnchors(UUID nodeId, ServerWebExchange exchange) {
		return withPermission(PlatformPermissions.NODE_ENROLL, subject -> nodeLifecycle.hostAnchors(nodeId)
				.collectList().map(anchors -> ResponseEntity.ok(toAnchors(nodeId, anchors))));
	}

	// node:enroll, not a new permission: this writes exactly what registration
	// writes, so a principal that can enroll a node can already put any anchor on
	// one it enrolls.
	@Override
	public Mono<ResponseEntity<NodeHostAnchors>> replaceNodeHostAnchors(UUID nodeId,
			Mono<NodeHostAnchorsRequest> nodeHostAnchorsRequest, String idempotencyKey, ServerWebExchange exchange) {
		return nodeHostAnchorsRequest.flatMap(req -> withPermission(PlatformPermissions.NODE_ENROLL, subject -> {
			Mono<ResponseEntity<NodeHostAnchors>> action = nodeLifecycle
					.replaceHostAnchors(nodeId, req.getHostCertificate(), req.getPinnedHostKey(), subject.identity())
					.map(anchors -> ResponseEntity.ok(toAnchors(nodeId, anchors)));
			return idempotency.execute(idempotencyKey, subject.identity(), ApiConversions.method(exchange),
					ApiConversions.path(exchange), req, NodeHostAnchors.class, action);
		}));
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

	private static NodeHostAnchors toAnchors(UUID nodeId, List<NodeHostKey> anchors) {
		return new NodeHostAnchors(nodeId, anchors.stream().map(NodeController::toAnchor).toList());
	}

	// fingerprint and recordedAt stay absent rather than being manufactured: a
	// host_ca anchor recorded from a certificate line has no fingerprint to
	// compare.
	private static NodeHostAnchor toAnchor(NodeHostKey key) {
		NodeHostAnchor anchor = new NodeHostAnchor(NodeHostAnchor.SourceEnum.fromValue(key.source()), key.keyType());
		anchor.setFingerprint(key.fingerprint());
		anchor.setRecordedAt(toOffset(key.createdAt()));
		return anchor;
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
