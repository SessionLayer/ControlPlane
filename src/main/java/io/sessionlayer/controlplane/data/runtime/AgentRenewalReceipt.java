package io.sessionlayer.controlplane.data.runtime;

import io.sessionlayer.controlplane.data.Uuids;
import java.time.Instant;
import java.util.UUID;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.Id;
import org.springframework.data.relational.core.mapping.Table;

@Table(schema = "runtime", name = "agent_renewal_receipt")
public record AgentRenewalReceipt(@Id UUID id, UUID agentId, long priorGeneration, String csrPublicKeyHash,
		long newGeneration, byte[] certificate, byte[] caCertificate, Instant notBefore, Instant notAfter,
		@CreatedDate Instant createdAt, Instant expiresAt) {

	public static AgentRenewalReceipt create(UUID agentId, long priorGeneration, String csrPublicKeyHash,
			long newGeneration, byte[] certificate, byte[] caCertificate, Instant notBefore, Instant notAfter,
			Instant expiresAt) {
		return new AgentRenewalReceipt(Uuids.v7(), agentId, priorGeneration, csrPublicKeyHash, newGeneration,
				certificate, caCertificate, notBefore, notAfter, null, expiresAt);
	}
}
