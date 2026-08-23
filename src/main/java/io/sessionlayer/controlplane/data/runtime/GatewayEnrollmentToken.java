package io.sessionlayer.controlplane.data.runtime;

import io.sessionlayer.controlplane.data.Uuids;
import java.time.Instant;
import java.util.UUID;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.Id;
import org.springframework.data.annotation.Version;
import org.springframework.data.relational.core.mapping.Table;

@Table(schema = "runtime", name = "gateway_enrollment_token")
public record GatewayEnrollmentToken(@Id UUID id, String tokenHash, String gatewayName, boolean singleUse,
		Instant expiresAt, Instant consumedAt, String createdBy, @Version Long version,
		@CreatedDate Instant createdAt) {

	public static GatewayEnrollmentToken create(String tokenHash, String gatewayName, Instant expiresAt,
			String createdBy) {
		return new GatewayEnrollmentToken(Uuids.v7(), tokenHash, gatewayName, true, expiresAt, null, createdBy, null,
				null);
	}
}
