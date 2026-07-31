package io.sessionlayer.controlplane.data.config;

import io.sessionlayer.controlplane.data.Uuids;
import java.time.Instant;
import java.util.UUID;
import org.springframework.data.annotation.Id;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.annotation.Version;
import org.springframework.data.relational.core.mapping.Table;

@Table(schema = "config", name = "policy_epoch")
public record PolicyEpoch(@Id UUID id, boolean singleton, long epoch, @Version Long version,
		@LastModifiedDate Instant updatedAt) {

	public static PolicyEpoch initial() {
		return new PolicyEpoch(Uuids.v7(), true, 0L, null, null);
	}
}
