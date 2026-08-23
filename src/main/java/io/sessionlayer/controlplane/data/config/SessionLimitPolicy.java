package io.sessionlayer.controlplane.data.config;

import io.sessionlayer.controlplane.data.Uuids;
import java.time.Instant;
import java.util.UUID;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.Id;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.annotation.Version;
import org.springframework.data.relational.core.mapping.Table;
import tools.jackson.databind.JsonNode;

@Table(schema = "config", name = "session_limit_policy")
public record SessionLimitPolicy(@Id UUID id, String name, JsonNode identitySelector, Integer maxConcurrentSessions,
		Integer maxSessionSeconds, Integer idleTimeoutSeconds, String origin, @Version Long version,
		@CreatedDate Instant createdAt, @LastModifiedDate Instant updatedAt) {

	public static SessionLimitPolicy create(String name, JsonNode identitySelector, Integer maxConcurrentSessions,
			Integer maxSessionSeconds, Integer idleTimeoutSeconds, String origin) {
		return new SessionLimitPolicy(Uuids.v7(), name, identitySelector, maxConcurrentSessions, maxSessionSeconds,
				idleTimeoutSeconds, origin, null, null, null);
	}
}
