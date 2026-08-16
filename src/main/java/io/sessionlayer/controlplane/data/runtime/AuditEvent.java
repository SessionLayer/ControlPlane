package io.sessionlayer.controlplane.data.runtime;

import io.sessionlayer.controlplane.data.Uuids;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.Id;
import org.springframework.data.annotation.ReadOnlyProperty;
import org.springframework.data.annotation.Version;
import org.springframework.data.relational.core.mapping.Table;
import tools.jackson.databind.JsonNode;

/**
 * Unified audit stream (SSH + web/admin). Append-only (DB trigger rejects
 * UPDATE/DELETE). FK-free (correlation by id). Hash chain via
 * prevHash/recordHash. No updatedAt. seq is DB-assigned monotonic order
 * (ReadOnly, assigned by Postgres).
 */
@Table(schema = "runtime", name = "audit_event")
public record AuditEvent(@Id UUID id, Instant occurredAt, String actor, String subject, String action, String outcome,
		UUID correlationId, UUID sessionId, UUID nodeId, JsonNode nodeLabels, String sourceIp, String accessModel,
		List<String> capabilities, JsonNode detail, String prevHash, String recordHash, @Version Long version,
		@CreatedDate Instant createdAt, @ReadOnlyProperty Long seq) {

	public static AuditEvent create(Instant occurredAt, String actor, String subject, String action, String outcome,
			UUID correlationId, UUID sessionId, UUID nodeId, JsonNode nodeLabels, String sourceIp, String accessModel,
			List<String> capabilities, JsonNode detail) {
		return new AuditEvent(Uuids.v7(), occurredAt, actor, subject, action, outcome, correlationId, sessionId, nodeId,
				nodeLabels, sourceIp, accessModel, capabilities, detail, null, null, null, null, null);
	}

	public AuditEvent withChain(String prevHash, String recordHash) {
		return new AuditEvent(id, occurredAt, actor, subject, action, outcome, correlationId, sessionId, nodeId,
				nodeLabels, sourceIp, accessModel, capabilities, detail, prevHash, recordHash, version, createdAt, seq);
	}

	/**
	 * Drop the tamper-evidence columns for a scope-filtered read. A sequence number
	 * over a filtered view discloses the existence and count of the events that
	 * were filtered out, and a linkage walk over a filtered view proves nothing
	 * about the rows it never saw.
	 */
	public AuditEvent withoutChain() {
		return new AuditEvent(id, occurredAt, actor, subject, action, outcome, correlationId, sessionId, nodeId,
				nodeLabels, sourceIp, accessModel, capabilities, detail, null, null, version, createdAt, null);
	}
}
