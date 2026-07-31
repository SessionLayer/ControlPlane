package io.sessionlayer.controlplane.data.runtime;

import io.sessionlayer.controlplane.data.Uuids;
import java.time.Instant;
import java.util.UUID;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.Id;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.annotation.Version;
import org.springframework.data.relational.core.mapping.Table;

@Table(schema = "runtime", name = "breakglass_activation")
public record BreakglassActivation(@Id UUID id, String principal, String reason, String alertRef,
		UUID breakglassPolicyId, String breakglassPolicyName, String reviewStatus, String reviewer, Instant activatedAt,
		Instant reviewedAt, String identity, String sourceIp, UUID targetNodeId, String credentialRef,
		@Version Long version, @CreatedDate Instant createdAt, @LastModifiedDate Instant updatedAt) {

	public static BreakglassActivation activate(String identity, String principal, String reason, String alertRef,
			UUID breakglassPolicyId, String breakglassPolicyName, String sourceIp, UUID targetNodeId,
			String credentialRef, Instant activatedAt) {
		return new BreakglassActivation(Uuids.v7(), principal, reason, alertRef, breakglassPolicyId,
				breakglassPolicyName, "pending", null, activatedAt, null, identity, sourceIp, targetNodeId,
				credentialRef, null, null, null);
	}

	public BreakglassActivation reviewed(String reviewer, Instant at) {
		return new BreakglassActivation(id, principal, reason, alertRef, breakglassPolicyId, breakglassPolicyName,
				"reviewed", reviewer, activatedAt, at, identity, sourceIp, targetNodeId, credentialRef, version,
				createdAt, updatedAt);
	}
}
