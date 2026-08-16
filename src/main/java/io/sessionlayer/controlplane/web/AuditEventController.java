package io.sessionlayer.controlplane.web;

import io.sessionlayer.controlplane.api.AuditEventsApi;
import io.sessionlayer.controlplane.api.model.AccessModel;
import io.sessionlayer.controlplane.api.model.AuditEventPage;
import io.sessionlayer.controlplane.api.model.AuditEventResource;
import io.sessionlayer.controlplane.api.model.Capability;
import io.sessionlayer.controlplane.audit.AuditEventSearchService;
import io.sessionlayer.controlplane.audit.AuditEventStore.AuditPage;
import io.sessionlayer.controlplane.audit.AuditEventStore.AuditQuery;
import io.sessionlayer.controlplane.data.runtime.AuditEvent;
import io.sessionlayer.controlplane.platform.PlatformAuthorization;
import io.sessionlayer.controlplane.platform.PlatformAuthorization.ScopeGrant;
import io.sessionlayer.controlplane.platform.PlatformPermissions;
import io.sessionlayer.controlplane.security.CurrentAuthentication;
import java.time.Duration;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

@RestController
public class AuditEventController implements AuditEventsApi {

	private final AuditEventSearchService search;
	private final PlatformAuthorization platformAuthorization;
	private final CurrentAuthentication currentAuthentication;
	private final ObjectMapper objectMapper;
	private final AuditSearchProperties properties;

	public AuditEventController(AuditEventSearchService search, PlatformAuthorization platformAuthorization,
			CurrentAuthentication currentAuthentication, ObjectMapper objectMapper, AuditSearchProperties properties) {
		this.search = search;
		this.platformAuthorization = platformAuthorization;
		this.currentAuthentication = currentAuthentication;
		this.objectMapper = objectMapper;
		this.properties = properties;
	}

	@Override
	public Mono<ResponseEntity<AuditEventPage>> searchAuditEvents(String cursor, Integer limit, String actor,
			String subject, String action, String outcome, UUID sessionId, UUID nodeId, String sourceIp,
			OffsetDateTime from, OffsetDateTime to, Capability capability, AccessModel accessModel,
			List<String> nodeLabel, UUID correlationId, ServerWebExchange exchange) {
		return currentAuthentication.subject().flatMap(caller -> platformAuthorization
				.resolveScopeGrant(caller, PlatformPermissions.AUDIT_READ).flatMap(grant -> {
					if (!grant.granted()) {
						return forbidden();
					}
					Window window = resolveWindow(from == null ? null : from.toInstant(),
							to == null ? null : to.toInstant());
					AuditQuery query = new AuditQuery(actor, subject, action, outcome, sessionId, nodeId, sourceIp,
							window.from(), window.to(), capability == null ? null : capability.getValue(),
							accessModel == null ? null : accessModel.getValue(), parseLabels(nodeLabel), correlationId,
							scopeGrants(grant), cursor, CursorPages.clamp(limit));
					return search.search(query, caller.identity()).map(page -> ResponseEntity.ok(toPage(page)));
				})).switchIfEmpty(forbidden());
	}

	@Override
	public Mono<ResponseEntity<AuditEventResource>> getAuditEvent(UUID auditEventId, ServerWebExchange exchange) {
		return currentAuthentication.subject().flatMap(caller -> platformAuthorization
				.resolveScopeGrant(caller, PlatformPermissions.AUDIT_READ).flatMap(grant -> {
					if (!grant.granted()) {
						return Mono.just(ResponseEntity.status(HttpStatus.FORBIDDEN).<AuditEventResource>build());
					}
					return search.get(auditEventId, caller.identity(), grant)
							.map(event -> ResponseEntity.ok(toResource(event))).switchIfEmpty(notFound());
				})).switchIfEmpty(Mono.just(ResponseEntity.status(HttpStatus.FORBIDDEN).<AuditEventResource>build()));
	}

	private static List<JsonNode> scopeGrants(ScopeGrant grant) {
		return grant.unrestricted() ? List.of() : grant.scopes();
	}

	// Out-of-scope and absent return the same response; prevents probing for
	// the existence of events outside the caller's scope.
	private static Mono<ResponseEntity<AuditEventResource>> notFound() {
		return Mono.just(ResponseEntity.notFound().<AuditEventResource>build());
	}

	private static Mono<ResponseEntity<AuditEventPage>> forbidden() {
		return Mono.just(ResponseEntity.status(HttpStatus.FORBIDDEN).<AuditEventPage>build());
	}

	private static Map<String, String> parseLabels(List<String> nodeLabel) {
		if (nodeLabel == null || nodeLabel.isEmpty()) {
			return Map.of();
		}
		Map<String, String> labels = new LinkedHashMap<>();
		for (String pair : nodeLabel) {
			int eq = pair == null ? -1 : pair.indexOf('=');
			if (eq > 0) {
				labels.put(pair.substring(0, eq), pair.substring(eq + 1));
			}
		}
		return labels;
	}

	private Window resolveWindow(Instant from, Instant to) {
		Duration max = properties.getMaxWindow();
		if (from != null && to != null) {
			if (Duration.between(from, to).compareTo(max) > 0) {
				throw tooWide(max);
			}
			return new Window(from, to);
		}
		Instant now = Instant.now();
		if (from != null) {
			if (Duration.between(from, now).compareTo(max) > 0) {
				throw tooWide(max);
			}
			return new Window(from, null);
		}
		if (to != null) {
			return new Window(to.minus(max), to);
		}
		return new Window(now.minus(properties.getDefaultWindow()), null);
	}

	private static ApiProblemException tooWide(Duration max) {
		return ApiProblemException.validation("audit search time window exceeds the maximum of " + max);
	}

	private record Window(Instant from, Instant to) {
	}

	private AuditEventPage toPage(AuditPage page) {
		return new AuditEventPage(page.items().stream().map(this::toResource).toList()).nextCursor(page.nextCursor());
	}

	private AuditEventResource toResource(AuditEvent event) {
		AuditEventResource resource = new AuditEventResource(event.id(), ApiConversions.toOffset(event.occurredAt()),
				event.actor(), event.action(), event.outcome());
		resource.setSubject(event.subject());
		resource.setSessionId(event.sessionId());
		resource.setNodeId(event.nodeId());
		resource.setCorrelationId(event.correlationId());
		resource.setSourceIp(event.sourceIp());
		resource.setCapabilities(event.capabilities());
		resource.setNodeLabels(labelMap(event.nodeLabels()));
		resource.setDetail(ApiConversions.toMap(objectMapper, event.detail()));
		// Copied unconditionally: AuditEventSearchService has already stripped these
		// for a scope-filtered read, so there is no visibility decision to forget here.
		resource.setSeq(event.seq());
		resource.setPrevHash(event.prevHash());
		resource.setRecordHash(event.recordHash());
		return resource;
	}

	private static Map<String, String> labelMap(JsonNode node) {
		if (node == null || !node.isObject()) {
			return null;
		}
		Map<String, String> labels = new LinkedHashMap<>();
		for (Map.Entry<String, JsonNode> entry : node.properties()) {
			if (entry.getValue() != null && entry.getValue().isString()) {
				labels.put(entry.getKey(), entry.getValue().stringValue());
			}
		}
		return labels;
	}
}
