package io.sessionlayer.controlplane.audit;

import io.sessionlayer.controlplane.data.runtime.AuditEvent;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import reactor.core.publisher.Mono;
import tools.jackson.databind.JsonNode;

public interface AuditEventStore {

	default Mono<Void> record(String actor, String subject, String action, String outcome, UUID sessionId, UUID nodeId,
			Map<String, String> detail) {
		return record(AuditRecord.of(actor, subject, action, outcome, sessionId, nodeId, detail));
	}

	Mono<Void> record(AuditRecord record);

	/**
	 * Append a config-change event capturing before/after state. The two objects
	 * MUST be secret-free (config exposes references, never key material).
	 */
	Mono<Void> recordChange(String actor, String subject, String action, Map<String, String> detail, Object before,
			Object after);

	Mono<AuditPage> search(AuditQuery query);

	Mono<AuditEvent> findById(UUID id);

	Mono<AuditChainVerifier.Result> verifyChain();

	/**
	 * Full dimension set. Producer must validate sourceIp (valid IP/CIDR literal)
	 * and capabilities (raw vocab) - bad values violate column CHECK and roll back
	 * the enclosing transaction.
	 */
	record AuditRecord(String actor, String subject, String action, String outcome, UUID sessionId, UUID nodeId,
			Map<String, String> detail, String sourceIp, String accessModel, List<String> capabilities,
			Map<String, String> nodeLabels, UUID correlationId) {

		public AuditRecord {
			detail = (detail == null) ? null : Map.copyOf(detail);
			capabilities = (capabilities == null) ? null : List.copyOf(capabilities);
			nodeLabels = (nodeLabels == null) ? null : Map.copyOf(nodeLabels);
		}

		public static AuditRecord of(String actor, String subject, String action, String outcome, UUID sessionId,
				UUID nodeId, Map<String, String> detail) {
			return new AuditRecord(actor, subject, action, outcome, sessionId, nodeId, detail, null, null, null, null,
					null);
		}

		public static Builder builder(String actor, String subject, String action, String outcome) {
			return new Builder(actor, subject, action, outcome);
		}

		public static final class Builder {

			private final String actor;
			private final String subject;
			private final String action;
			private final String outcome;
			private UUID sessionId;
			private UUID nodeId;
			private Map<String, String> detail;
			private String sourceIp;
			private String accessModel;
			private List<String> capabilities;
			private Map<String, String> nodeLabels;
			private UUID correlationId;

			private Builder(String actor, String subject, String action, String outcome) {
				this.actor = actor;
				this.subject = subject;
				this.action = action;
				this.outcome = outcome;
			}

			public Builder session(UUID sessionId) {
				this.sessionId = sessionId;
				return this;
			}

			public Builder node(UUID nodeId) {
				this.nodeId = nodeId;
				return this;
			}

			public Builder detail(Map<String, String> detail) {
				this.detail = detail;
				return this;
			}

			public Builder sourceIp(String sourceIp) {
				this.sourceIp = sourceIp;
				return this;
			}

			public Builder accessModel(String accessModel) {
				this.accessModel = accessModel;
				return this;
			}

			public Builder capabilities(List<String> capabilities) {
				this.capabilities = capabilities;
				return this;
			}

			public Builder nodeLabels(Map<String, String> nodeLabels) {
				this.nodeLabels = nodeLabels;
				return this;
			}

			public Builder correlationId(UUID correlationId) {
				this.correlationId = correlationId;
				return this;
			}

			public AuditRecord build() {
				return new AuditRecord(actor, subject, action, outcome, sessionId, nodeId, detail, sourceIp,
						accessModel, capabilities, nodeLabels, correlationId);
			}
		}
	}

	record AuditPage(List<AuditEvent> items, String nextCursor) {
	}

	/**
	 * A resolved audit-search query: the caller-supplied filter dimensions plus the
	 * RBAC {@code scopeGrants} the search must be confined to and the keyset
	 * {@code cursor}/{@code limit}. A null/blank filter is unrestricted for that
	 * dimension.
	 *
	 * @param nodeLabels
	 *            snapshot node labels that must all be present (AND)
	 * @param scopeGrants
	 *            the caller's scoped {@code audit:read} grants (each a
	 *            {@code role_binding.scope} object) OR-ed together; <b>empty means
	 *            unrestricted</b> (the caller holds an unscoped grant) - the
	 *            controller must have already denied a caller with no grant at all
	 */
	record AuditQuery(String actor, String subject, String action, String outcome, UUID sessionId, UUID nodeId,
			String sourceIp, Instant from, Instant to, String capability, String accessModel,
			Map<String, String> nodeLabels, UUID correlationId, List<JsonNode> scopeGrants, String cursor, int limit) {

		public AuditQuery {
			nodeLabels = (nodeLabels == null) ? Map.of() : Map.copyOf(nodeLabels);
			scopeGrants = (scopeGrants == null) ? List.of() : List.copyOf(scopeGrants);
		}
	}
}
