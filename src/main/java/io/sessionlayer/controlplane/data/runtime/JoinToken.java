package io.sessionlayer.controlplane.data.runtime;

import io.sessionlayer.controlplane.data.Uuids;
import java.time.Instant;
import java.util.UUID;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.Id;
import org.springframework.data.annotation.Version;
import org.springframework.data.relational.core.mapping.Table;
import tools.jackson.databind.JsonNode;

@Table(schema = "runtime", name = "join_token")
public record JoinToken(@Id UUID id, String tokenHash, JsonNode scope, String joinMethod, UUID nodeId,
		boolean singleUse, Instant expiresAt, Instant consumedAt, String createdBy, @Version Long version,
		@CreatedDate Instant createdAt) {

	public static JoinToken create(String tokenHash, JsonNode scope, String joinMethod, UUID nodeId, boolean singleUse,
			Instant expiresAt, String createdBy) {
		return new JoinToken(Uuids.v7(), tokenHash, scope, joinMethod, nodeId, singleUse, expiresAt, null, createdBy,
				null, null);
	}
}
