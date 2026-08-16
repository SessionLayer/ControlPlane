package io.sessionlayer.controlplane.authz;

import io.sessionlayer.controlplane.audit.AuditEventStore;
import io.sessionlayer.controlplane.audit.AuditEventStore.AuditRecord;
import io.sessionlayer.controlplane.data.runtime.NodeRepository;
import io.sessionlayer.controlplane.data.runtime.SessionLeaseRepository;
import io.sessionlayer.controlplane.data.runtime.SshSession;
import io.sessionlayer.controlplane.data.runtime.SshSessionRepository;
import io.sessionlayer.controlplane.gateway.GatewayRequestException;
import io.sessionlayer.controlplane.gateway.GatewayRequestException.Reason;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.OptimisticLockingFailureException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.reactive.TransactionalOperator;
import reactor.core.publisher.Mono;
import reactor.util.retry.Retry;
import tools.jackson.databind.JsonNode;

@Service
public class SessionLifecycleService {

	private static final Logger LOG = LoggerFactory.getLogger(SessionLifecycleService.class);

	private final SshSessionRepository sshSessions;
	private final SessionLeaseRepository sessionLeases;
	private final NodeRepository nodes;
	private final SessionLimitProperties properties;
	private final AuditEventStore audit;
	private final TransactionalOperator tx;

	public SessionLifecycleService(SshSessionRepository sshSessions, SessionLeaseRepository sessionLeases,
			NodeRepository nodes, SessionLimitProperties properties, AuditEventStore audit, TransactionalOperator tx) {
		this.sshSessions = sshSessions;
		this.sessionLeases = sessionLeases;
		this.nodes = nodes;
		this.properties = properties;
		this.audit = audit;
		this.tx = tx;
	}

	public Mono<Boolean> endSession(UUID callerGatewayId, UUID sessionId, String reason) {
		if (callerGatewayId == null || sessionId == null) {
			return Mono.error(refused());
		}
		Mono<Boolean> body = sshSessions.findById(sessionId).switchIfEmpty(Mono.error(refused())).flatMap(session -> {
			if (!callerGatewayId.equals(session.gatewayId())) {
				return Mono.error(refused());
			}
			Instant now = Instant.now();
			Mono<Void> stampEnd = session.endedAt() == null
					? sshSessions.save(session.ended(now, reason)).then()
					: Mono.empty();
			boolean stamped = session.endedAt() == null;
			return stampEnd.then(sessionLeases.releaseBySessionId(sessionId, now))
					.flatMap(released -> auditEnd(callerGatewayId, session, reason, stamped, released > 0)
							.thenReturn(released > 0));
		});
		// A lost @Version race with FinalizeRecording's end-stamp retries once: the
		// re-read sees the session already ended, skips the stamp, and releases the
		// lease idempotently.
		return tx.transactional(body)
				.retryWhen(Retry.max(1).filter(OptimisticLockingFailureException.class::isInstance));
	}

	public Mono<Instant> extendLease(UUID callerGatewayId, UUID sessionId) {
		if (callerGatewayId == null || sessionId == null) {
			return Mono.error(refused());
		}
		return sshSessions.findById(sessionId).switchIfEmpty(Mono.error(refused())).flatMap(session -> {
			if (!callerGatewayId.equals(session.gatewayId())) {
				return Mono.error(refused());
			}
			if (session.endedAt() != null) {
				return Mono.error(new GatewayRequestException(Reason.FAILED_PRECONDITION, "session already ended"));
			}
			Instant expiry = Instant.now().plus(properties.getLeaseExtension());
			return sessionLeases.extendBySessionId(sessionId, expiry).flatMap(rows -> {
				if (rows > 0) {
					return Mono.just(expiry);
				}
				LOG.warn("ExtendSessionLease refused for live session {}: lease already released/absent — if the "
						+ "reaper released it mid-run, concurrency under-counts until the session ends (check "
						+ "sessionlayer.session-limits.reaper.grace vs the Gateway extend cadence)", sessionId);
				return Mono.error(new GatewayRequestException(Reason.FAILED_PRECONDITION, "lease not extendable"));
			});
		});
	}

	private Mono<Void> auditEnd(UUID callerGatewayId, SshSession session, String reason, boolean stamped,
			boolean released) {
		if (!stamped && !released) {
			return Mono.empty();
		}
		Map<String, String> detail = new HashMap<>();
		detail.put("gateway_id", callerGatewayId.toString());
		detail.put("reason", reason);
		detail.put("lease_released", Boolean.toString(released));
		return nodeLabels(session.nodeId()).flatMap(labels -> audit
				.record(AuditRecord.builder(callerGatewayId.toString(), session.identity(), "session.end", "success")
						.session(session.id()).node(session.nodeId()).accessModel(session.accessModel())
						.nodeLabels(labels).correlationId(session.correlationId()).detail(detail).build()));
	}

	private Mono<Map<String, String>> nodeLabels(UUID nodeId) {
		if (nodeId == null) {
			return Mono.just(Map.of());
		}
		return nodes.findById(nodeId).map(node -> labelsOf(node.resolvedLabels())).defaultIfEmpty(Map.of());
	}

	private static Map<String, String> labelsOf(JsonNode resolvedLabels) {
		Map<String, String> labels = new HashMap<>();
		if (resolvedLabels != null && resolvedLabels.isObject()) {
			for (var entry : resolvedLabels.properties()) {
				labels.put(entry.getKey(), entry.getValue().asString());
			}
		}
		return labels;
	}

	private static GatewayRequestException refused() {
		return new GatewayRequestException(Reason.PERMISSION_DENIED, "session lifecycle request refused");
	}
}
