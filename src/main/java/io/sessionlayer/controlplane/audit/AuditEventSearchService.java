package io.sessionlayer.controlplane.audit;

import io.sessionlayer.controlplane.audit.AuditEventStore.AuditPage;
import io.sessionlayer.controlplane.audit.AuditEventStore.AuditQuery;
import io.sessionlayer.controlplane.data.runtime.AuditEvent;
import io.sessionlayer.controlplane.platform.PlatformAuthorization.ScopeGrant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

@Service
public class AuditEventSearchService {

	private final AuditEventStore store;

	public AuditEventSearchService(AuditEventStore store) {
		this.store = store;
	}

	/**
	 * Run the RBAC-scoped search, then audit the access. Auditing AFTER the query
	 * keeps a malformed request (e.g. a bad cursor, which errors on subscribe) from
	 * recording a served-search event, and keeps the returned page from including
	 * the very {@code audit.search} row it generated.
	 */
	public Mono<AuditPage> search(AuditQuery query, String actor) {
		return store.search(query)
				.map(page -> new AuditPage(visible(page.items(), query.scopeGrants().isEmpty()), page.nextCursor()))
				.flatMap(page -> auditAccess(actor, null, "audit.search", summarize(query)).thenReturn(page));
	}

	/**
	 * Audit the access up front, then apply the caller's grant to the loaded event.
	 * Auditing first records the attempt even when the id is absent or out of the
	 * caller's scope (both resolve to an empty result, which the controller renders
	 * as an indistinguishable 404) — an out-of-scope probe is exactly what an audit
	 * trail should capture. The grant is a parameter rather than a downstream check
	 * so no caller can obtain an event this service has not already filtered.
	 */
	public Mono<AuditEvent> get(UUID id, String actor, ScopeGrant grant) {
		return auditAccess(actor, id.toString(), "audit.get", Map.of("audit_event_id", id.toString()))
				.then(store.findById(id))
				.filter(event -> grant.unrestricted() || AuditScopeMatcher.inScope(event, grant.scopes()))
				.map(event -> visible(event, grant.unrestricted()));
	}

	private static AuditEvent visible(AuditEvent event, boolean unrestricted) {
		return unrestricted ? event : event.withoutChain();
	}

	private static List<AuditEvent> visible(List<AuditEvent> events, boolean unrestricted) {
		return unrestricted ? events : events.stream().map(AuditEvent::withoutChain).toList();
	}

	private Mono<Void> auditAccess(String actor, String subject, String action, Map<String, String> detail) {
		return store.record(actor, subject, action, "success", null, null, detail);
	}

	private static Map<String, String> summarize(AuditQuery q) {
		Map<String, String> detail = new LinkedHashMap<>();
		put(detail, "actor", q.actor());
		put(detail, "subject", q.subject());
		put(detail, "action", q.action());
		put(detail, "outcome", q.outcome());
		put(detail, "session_id", q.sessionId());
		put(detail, "node_id", q.nodeId());
		put(detail, "source_ip", q.sourceIp());
		put(detail, "from", q.from());
		put(detail, "to", q.to());
		put(detail, "capability", q.capability());
		put(detail, "access_model", q.accessModel());
		put(detail, "correlation_id", q.correlationId());
		if (!q.nodeLabels().isEmpty()) {
			detail.put("node_labels", q.nodeLabels().toString());
		}
		detail.put("scoped", Boolean.toString(!q.scopeGrants().isEmpty()));
		return detail;
	}

	private static void put(Map<String, String> detail, String key, Object value) {
		if (value != null && !(value instanceof String s && s.isBlank())) {
			detail.put(key, value.toString());
		}
	}
}
