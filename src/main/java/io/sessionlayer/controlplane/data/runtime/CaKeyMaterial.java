package io.sessionlayer.controlplane.data.runtime;

import io.sessionlayer.controlplane.data.Uuids;
import java.time.Instant;
import java.util.UUID;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.Id;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.annotation.Version;
import org.springframework.data.relational.core.mapping.Table;

@Table(schema = "runtime", name = "ca_key_material")
public record CaKeyMaterial(@Id UUID id, UUID caConfigId, String caConfigName, String wrapAlgorithm,
		String kekReference, byte[] wrappedKey, byte[] iv, byte[] publicKey, String keyType, byte[] caCertificate,
		String keyLocation, @Version Long version, @CreatedDate Instant createdAt,
		@LastModifiedDate Instant updatedAt) {

	public static final String LOCAL_KEK = "local_kek";
	public static final String EXTERNAL = "external";

	public static CaKeyMaterial create(UUID caConfigId, String caConfigName, String kekReference, byte[] wrappedKey,
			byte[] iv, byte[] publicKey, String keyType) {
		return create(caConfigId, caConfigName, kekReference, wrappedKey, iv, publicKey, keyType, null);
	}

	public static CaKeyMaterial create(UUID caConfigId, String caConfigName, String kekReference, byte[] wrappedKey,
			byte[] iv, byte[] publicKey, String keyType, byte[] caCertificate) {
		return new CaKeyMaterial(Uuids.v7(), caConfigId, caConfigName, "AES-256-GCM", kekReference, wrappedKey, iv,
				publicKey, keyType, caCertificate, LOCAL_KEK, null, null, null);
	}

	/**
	 * An external (key-service) CA row: the private key lives in the key service,
	 * so wrappedKey/iv/kekReference are absent - the schema refuses any other shape
	 * for {@code key_location = 'external'}.
	 */
	public static CaKeyMaterial createExternal(UUID caConfigId, String caConfigName, byte[] publicKey, String keyType,
			byte[] caCertificate) {
		return new CaKeyMaterial(Uuids.v7(), caConfigId, caConfigName, "AES-256-GCM", null, null, null, publicKey,
				keyType, caCertificate, EXTERNAL, null, null, null);
	}
}
