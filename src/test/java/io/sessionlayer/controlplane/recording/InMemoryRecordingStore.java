package io.sessionlayer.controlplane.recording;

import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import reactor.core.publisher.Mono;

public class InMemoryRecordingStore implements RecordingStore {

	static final String BASE_URL = "https://in-memory.test/";

	private final Set<String> objects = ConcurrentHashMap.newKeySet();

	void seed(String objectKey) {
		objects.add(objectKey);
	}

	boolean contains(String objectKey) {
		return objects.contains(objectKey);
	}

	@Override
	public Mono<Void> ensureReady() {
		return Mono.empty();
	}

	@Override
	public Mono<PresignedAccess> presignUpload(String objectKey, String wormMode, Instant retainUntil) {
		objects.add(objectKey);
		return Mono.just(new PresignedAccess(BASE_URL + objectKey, "PUT", Map.of(), retainUntil.getEpochSecond()));
	}

	@Override
	public Mono<PresignedAccess> presignDownload(String objectKey, String objectVersionId, Duration ttl) {
		String url = (objectVersionId == null || objectVersionId.isBlank())
				? BASE_URL + objectKey
				: BASE_URL + objectKey + "?versionId=" + objectVersionId;
		return Mono.just(new PresignedAccess(url, "GET", Map.of(), Instant.now().plus(ttl).getEpochSecond()));
	}

	@Override
	public Mono<Void> deleteObject(String objectKey, String wormMode) {
		if ("compliance".equals(wormMode)) {
			return Mono.error(new UnsupportedOperationException("compliance-mode recordings are un-deletable"));
		}
		objects.remove(objectKey);
		return Mono.empty();
	}

	@Override
	public Mono<Void> probe() {
		return Mono.empty();
	}
}
