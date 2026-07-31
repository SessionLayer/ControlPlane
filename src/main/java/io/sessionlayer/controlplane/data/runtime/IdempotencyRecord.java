package io.sessionlayer.controlplane.data.runtime;

import io.sessionlayer.controlplane.data.Uuids;
import java.time.Instant;
import java.util.UUID;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.Id;
import org.springframework.data.annotation.Version;
import org.springframework.data.relational.core.mapping.Table;

@Table(schema = "runtime", name = "idempotency_key")
public record IdempotencyRecord(@Id UUID id, String principal, String method, String path, String idempotencyKey,
		String requestFingerprint, int responseStatus, String responseBody, @Version Long version,
		@CreatedDate Instant createdAt, Instant expiresAt) {

	public static IdempotencyRecord create(String principal, String method, String path, String idempotencyKey,
			String requestFingerprint, int responseStatus, String responseBody, Instant expiresAt) {
		return new IdempotencyRecord(Uuids.v7(), principal, method, path, idempotencyKey, requestFingerprint,
				responseStatus, responseBody, null, null, expiresAt);
	}
}
