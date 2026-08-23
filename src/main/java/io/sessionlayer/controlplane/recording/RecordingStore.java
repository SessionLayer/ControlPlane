package io.sessionlayer.controlplane.recording;

import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import reactor.core.publisher.Mono;

public interface RecordingStore {

	Mono<Void> ensureReady();

	Mono<PresignedAccess> presignUpload(String objectKey, String wormMode, Instant retainUntil);

	Mono<PresignedAccess> presignDownload(String objectKey, String objectVersionId, Duration ttl);

	Mono<Void> deleteObject(String objectKey, String wormMode);

	Mono<Void> probe();

	record PresignedAccess(String url, String method, Map<String, String> requiredHeaders, long expiresAtEpochSeconds) {
	}
}
