package io.sessionlayer.controlplane.data.config;

import io.sessionlayer.controlplane.data.Uuids;
import java.time.Instant;
import java.util.UUID;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.Id;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.annotation.Version;
import org.springframework.data.relational.core.mapping.Table;

@Table(schema = "config", name = "ca_config")
public record CaConfig(@Id UUID id, String name, String caKind, String backend, String keyReference, String algorithm,
		String rotationState, String origin, @Version Long version, @CreatedDate Instant createdAt,
		@LastModifiedDate Instant updatedAt) {

	public static CaConfig create(String name, String caKind, String backend, String keyReference, String algorithm,
			String rotationState, String origin) {
		return new CaConfig(Uuids.v7(), name, caKind, backend, keyReference, algorithm, rotationState, origin, null,
				null, null);
	}
}
