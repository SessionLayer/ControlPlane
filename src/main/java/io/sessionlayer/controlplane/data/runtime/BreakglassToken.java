package io.sessionlayer.controlplane.data.runtime;

import io.sessionlayer.controlplane.data.Uuids;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.Id;
import org.springframework.data.annotation.Version;
import org.springframework.data.relational.core.mapping.Table;

@Table(schema = "runtime", name = "breakglass_token")
public record BreakglassToken(@Id UUID id, String tokenHash, UUID gatewayId, String identity, UUID nodeId,
		List<String> allowedPrincipals, String sourceAddress, Instant expiresAt, boolean used, Instant usedAt,
		@Version Long version, @CreatedDate Instant createdAt) {

	public static BreakglassToken create(String tokenHash, UUID gatewayId, String identity, UUID nodeId,
			List<String> allowedPrincipals, String sourceAddress, Instant expiresAt) {
		return new BreakglassToken(Uuids.v7(), tokenHash, gatewayId, identity, nodeId, allowedPrincipals, sourceAddress,
				expiresAt, false, null, null, null);
	}

	public BreakglassToken consumed(Instant at) {
		return new BreakglassToken(id, tokenHash, gatewayId, identity, nodeId, allowedPrincipals, sourceAddress,
				expiresAt, true, at, version, createdAt);
	}
}
