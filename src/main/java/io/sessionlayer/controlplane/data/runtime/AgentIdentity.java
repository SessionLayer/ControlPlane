package io.sessionlayer.controlplane.data.runtime;

import io.sessionlayer.controlplane.data.Uuids;
import java.time.Instant;
import java.util.UUID;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.Id;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.annotation.Version;
import org.springframework.data.relational.core.mapping.Table;

@Table(schema = "runtime", name = "agent_identity")
public record AgentIdentity(@Id UUID id, UUID nodeId, String mtlsIdentityRef, String fingerprint,
		String prevFingerprint, long generation, String joinMethod, String status, Instant issuedAt, Instant notAfter,
		String statusReason, String statusChangedBy, Instant statusChangedAt, @Version Long version,
		@CreatedDate Instant createdAt, @LastModifiedDate Instant updatedAt) {

	public static AgentIdentity create(UUID nodeId, String mtlsIdentityRef, String fingerprint, long generation,
			String joinMethod, String status, Instant issuedAt, Instant notAfter) {
		return new AgentIdentity(Uuids.v7(), nodeId, mtlsIdentityRef, fingerprint, null, generation, joinMethod, status,
				issuedAt, notAfter, null, null, null, null, null, null);
	}
}
