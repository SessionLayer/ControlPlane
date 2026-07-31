package io.sessionlayer.controlplane.data.runtime;

import io.sessionlayer.controlplane.data.Uuids;
import java.time.Instant;
import java.util.UUID;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.Id;
import org.springframework.data.annotation.Version;
import org.springframework.data.relational.core.mapping.Table;

@Table(schema = "runtime", name = "recording_token")
public record RecordingToken(@Id UUID id, String tokenHash, UUID gatewayId, UUID sessionId, UUID nodeId,
		String principal, String sourceAddress, Instant expiresAt, boolean used, Instant usedAt, @Version Long version,
		@CreatedDate Instant createdAt) {

	public static RecordingToken create(String tokenHash, UUID gatewayId, UUID sessionId, UUID nodeId, String principal,
			String sourceAddress, Instant expiresAt) {
		return new RecordingToken(Uuids.v7(), tokenHash, gatewayId, sessionId, nodeId, principal, sourceAddress,
				expiresAt, false, null, null, null);
	}
}
