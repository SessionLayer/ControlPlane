package io.sessionlayer.controlplane.data.runtime;

import io.sessionlayer.controlplane.data.Uuids;
import java.time.Instant;
import java.util.UUID;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.Id;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.annotation.Version;
import org.springframework.data.relational.core.mapping.Table;

@Table(schema = "runtime", name = "gateway_identity")
public record GatewayIdentity(@Id UUID id, String name, String mtlsIdentityRef, String fingerprint,
		String prevFingerprint, long generation, String joinMethod, String status, Instant issuedAt, Instant notAfter,
		String statusReason, String statusChangedBy, Instant statusChangedAt, @Version Long version,
		@CreatedDate Instant createdAt, @LastModifiedDate Instant updatedAt) {

	public static GatewayIdentity create(String name, String mtlsIdentityRef, String fingerprint, long generation,
			String joinMethod, String status, Instant issuedAt, Instant notAfter) {
		return new GatewayIdentity(Uuids.v7(), name, mtlsIdentityRef, fingerprint, null, generation, joinMethod, status,
				issuedAt, notAfter, null, null, null, null, null, null);
	}
}
