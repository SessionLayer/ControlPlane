package io.sessionlayer.controlplane.data.runtime;

import java.time.Instant;
import java.util.UUID;
import org.springframework.data.annotation.Id;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.annotation.Version;
import org.springframework.data.relational.core.mapping.Table;

@Table(schema = "runtime", name = "presence")
public record Presence(@Id UUID nodeId, String owningGateway, String gatewayAddr, long nonce, UUID nonceId,
		Instant lastSeen, @Version Long version, @LastModifiedDate Instant updatedAt) {

	public static Presence create(UUID nodeId, String owningGateway, String gatewayAddr, long nonce, UUID nonceId,
			Instant lastSeen) {
		return new Presence(nodeId, owningGateway, gatewayAddr, nonce, nonceId, lastSeen, null, null);
	}
}
