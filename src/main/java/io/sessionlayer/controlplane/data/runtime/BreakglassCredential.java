package io.sessionlayer.controlplane.data.runtime;

import io.sessionlayer.controlplane.data.Uuids;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.Id;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.annotation.Version;
import org.springframework.data.relational.core.mapping.Table;
import tools.jackson.databind.JsonNode;

/**
 * FIDO2 sk-ecdsa PUBLIC break-glass key. PUBLIC material only; no private key
 * at rest.
 */
@Table(schema = "runtime", name = "breakglass_credential")
public record BreakglassCredential(@Id UUID id, String keyFingerprint, byte[] publicKey, String skApplication,
		String identity, List<String> allowedPrincipals, JsonNode nodeSelector, Instant expiresAt, Instant revokedAt,
		String createdBy, @Version Long version, @CreatedDate Instant createdAt, @LastModifiedDate Instant updatedAt) {

	public static BreakglassCredential register(String keyFingerprint, byte[] publicKey, String skApplication,
			String identity, List<String> allowedPrincipals, JsonNode nodeSelector, Instant expiresAt,
			String createdBy) {
		return new BreakglassCredential(Uuids.v7(), keyFingerprint, publicKey, skApplication, identity,
				allowedPrincipals, nodeSelector, expiresAt, null, createdBy, null, null, null);
	}

	public BreakglassCredential revoked(Instant at) {
		return new BreakglassCredential(id, keyFingerprint, publicKey, skApplication, identity, allowedPrincipals,
				nodeSelector, expiresAt, at, createdBy, version, createdAt, updatedAt);
	}

	public boolean active(Instant now) {
		return revokedAt == null && (expiresAt == null || expiresAt.isAfter(now));
	}
}
