package io.sessionlayer.controlplane.data.config;

import io.sessionlayer.controlplane.data.Uuids;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.Id;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.annotation.Version;
import org.springframework.data.relational.core.mapping.Table;
import tools.jackson.databind.JsonNode;

@Table(schema = "config", name = "dp_rule")
public record DpRule(@Id UUID id, String name, JsonNode identitySelector, JsonNode nodeLabelSelector,
		JsonNode sourceIpCondition, List<String> principals, Integer ttlSeconds, List<String> capabilities,
		String effect, String origin, @Version Long version, @CreatedDate Instant createdAt,
		@LastModifiedDate Instant updatedAt) {

	public static DpRule create(String name, JsonNode identitySelector, JsonNode nodeLabelSelector,
			JsonNode sourceIpCondition, List<String> principals, Integer ttlSeconds, List<String> capabilities,
			String effect, String origin) {
		return new DpRule(Uuids.v7(), name, identitySelector, nodeLabelSelector, sourceIpCondition, principals,
				ttlSeconds, capabilities, effect, origin, null, null, null);
	}
}
