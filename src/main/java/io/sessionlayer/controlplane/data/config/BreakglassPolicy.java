package io.sessionlayer.controlplane.data.config;

import io.sessionlayer.controlplane.data.Uuids;
import java.time.Instant;
import java.util.UUID;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.Id;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.annotation.Version;
import org.springframework.data.relational.core.mapping.Table;

@Table(schema = "config", name = "breakglass_policy")
public record BreakglassPolicy(@Id UUID id, String name, boolean recordingStrict, String alertTarget,
		boolean reviewRequired, String authPath, String origin, @Version Long version, @CreatedDate Instant createdAt,
		@LastModifiedDate Instant updatedAt) {

	public static BreakglassPolicy create(String name, boolean recordingStrict, String alertTarget,
			boolean reviewRequired, String authPath, String origin) {
		return new BreakglassPolicy(Uuids.v7(), name, recordingStrict, alertTarget, reviewRequired, authPath, origin,
				null, null, null);
	}
}
