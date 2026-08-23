package io.sessionlayer.controlplane.data.runtime;

import io.sessionlayer.controlplane.data.Uuids;
import java.time.Instant;
import java.util.UUID;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.Id;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.annotation.Version;
import org.springframework.data.relational.core.mapping.Table;
import tools.jackson.databind.JsonNode;

/**
 * RUNTIME · {@code runtime.node}. The columns {@code health} and
 * {@code owning_gateway} are deliberately unmapped: nothing ever updated them,
 * so they answered "unknown"/absent for the life of every node. Both are now
 * derived at read time from their real sources - {@code runtime.presence} and
 * {@code runtime.node_host_key} - and the columns survive only for the
 * expand/contract window.
 */
@Table(schema = "runtime", name = "node")
public record Node(@Id UUID id, String name, String nodePolicyName, JsonNode resolvedLabels, String connectorKind,
		String status, String address, String statusReason, String statusChangedBy, Instant statusChangedAt,
		@Version Long version, @CreatedDate Instant createdAt, @LastModifiedDate Instant updatedAt) {

	public static Node create(String name, String nodePolicyName, JsonNode resolvedLabels, String connectorKind,
			String status, String address) {
		return new Node(Uuids.v7(), name, nodePolicyName, resolvedLabels, connectorKind, status, address, null, null,
				null, null, null, null);
	}
}
