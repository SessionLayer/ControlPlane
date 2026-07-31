package io.sessionlayer.controlplane.data.runtime;

import io.sessionlayer.controlplane.data.Uuids;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.Id;
import org.springframework.data.annotation.Version;
import org.springframework.data.relational.core.mapping.Table;

@Table(schema = "runtime", name = "session_signing_token")
public record SessionSigningToken(@Id UUID id, String tokenHash, UUID gatewayId, UUID sessionId, UUID nodeId,
		String principal, List<String> capabilities, String sourceAddress, Instant expiresAt, boolean used,
		Instant usedAt, @Version Long version, @CreatedDate Instant createdAt) {

	public static SessionSigningToken create(String tokenHash, UUID gatewayId, UUID sessionId, UUID nodeId,
			String principal, List<String> capabilities, String sourceAddress, Instant expiresAt) {
		return new SessionSigningToken(Uuids.v7(), tokenHash, gatewayId, sessionId, nodeId, principal, capabilities,
				sourceAddress, expiresAt, false, null, null, null);
	}
}
