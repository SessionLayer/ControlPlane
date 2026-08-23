package io.sessionlayer.controlplane.data.runtime;

import io.sessionlayer.controlplane.data.Uuids;
import java.time.Instant;
import java.util.UUID;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.Id;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.annotation.Version;
import org.springframework.data.relational.core.mapping.Table;

@Table(schema = "runtime", name = "node_host_key")
public record NodeHostKey(@Id UUID id, UUID nodeId, String keyType, String publicKey, String fingerprint,
		String hostCertRef, String source, Instant verifiedAt, @Version Long version, @CreatedDate Instant createdAt,
		@LastModifiedDate Instant updatedAt) {

	public static NodeHostKey create(UUID nodeId, String keyType, String publicKey, String fingerprint,
			String hostCertRef, String source, Instant verifiedAt) {
		return new NodeHostKey(Uuids.v7(), nodeId, keyType, publicKey, fingerprint, hostCertRef, source, verifiedAt,
				null, null, null);
	}
}
