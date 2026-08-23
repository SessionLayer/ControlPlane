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

@Table(schema = "runtime", name = "access_lock")
public record AccessLock(@Id UUID id, JsonNode targetSelector, String mode, Integer ttlSeconds, Instant expiresAt,
		String reason, String createdBy, @Version Long version, @CreatedDate Instant createdAt,
		@LastModifiedDate Instant updatedAt) {

	public static AccessLock create(JsonNode targetSelector, String mode, Integer ttlSeconds, Instant expiresAt,
			String reason, String createdBy) {
		return new AccessLock(Uuids.v7(), targetSelector, mode, ttlSeconds, expiresAt, reason, createdBy, null, null,
				null);
	}
}
