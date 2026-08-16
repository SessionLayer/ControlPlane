package io.sessionlayer.controlplane.data.runtime;

import io.sessionlayer.controlplane.data.Uuids;
import java.time.Instant;
import java.util.UUID;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.Id;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.annotation.Version;
import org.springframework.data.relational.core.mapping.Table;

@Table(schema = "runtime", name = "recording_ref")
public record RecordingRef(@Id UUID id, UUID sessionId, String objectKey, String encryptionKeyRef, String hashChainHead,
		String wormMode, Long sizeBytes, Instant retentionUntil, boolean legalHold, String status, String format,
		String contentDigest, String objectVersionId, Instant prunedAt, String deleteMode, String deletedBy,
		String legalHoldReason, @Version Long version, @CreatedDate Instant createdAt,
		@LastModifiedDate Instant updatedAt) {

	public static RecordingRef create(UUID sessionId, String objectKey, String encryptionKeyRef, String hashChainHead,
			String wormMode, Long sizeBytes) {
		return new RecordingRef(Uuids.v7(), sessionId, objectKey, encryptionKeyRef, hashChainHead, wormMode, sizeBytes,
				null, false, "recording", "asciicast-v2", null, null, null, null, null, null, null, null, null);
	}

	public static RecordingRef begin(UUID id, UUID sessionId, String objectKey, String encryptionKeyRef,
			String wormMode, Instant retentionUntil) {
		return new RecordingRef(id, sessionId, objectKey, encryptionKeyRef, null, wormMode, null, retentionUntil, false,
				"recording", "asciicast-v2", null, null, null, null, null, null, null, null, null);
	}

	public RecordingRef finalized(String hashChainHead, String contentDigest, String objectVersionId, Long sizeBytes,
			String status) {
		return new RecordingRef(id, sessionId, objectKey, encryptionKeyRef,
				hashChainHead != null ? hashChainHead : this.hashChainHead, wormMode,
				sizeBytes != null ? sizeBytes : this.sizeBytes, retentionUntil, legalHold, status, format,
				contentDigest != null ? contentDigest : this.contentDigest,
				objectVersionId != null ? objectVersionId : this.objectVersionId, prunedAt, deleteMode, deletedBy,
				legalHoldReason, version, createdAt, updatedAt);
	}

	public RecordingRef withLegalHold(boolean held, String reason) {
		return new RecordingRef(id, sessionId, objectKey, encryptionKeyRef, hashChainHead, wormMode, sizeBytes,
				retentionUntil, held, status, format, contentDigest, objectVersionId, prunedAt, deleteMode, deletedBy,
				held ? reason : null, version, createdAt, updatedAt);
	}

	public RecordingRef pruned(String deleteMode, String deletedBy, Instant prunedAt) {
		return new RecordingRef(id, sessionId, objectKey, encryptionKeyRef, hashChainHead, wormMode, sizeBytes,
				retentionUntil, legalHold, status, format, contentDigest, objectVersionId, prunedAt, deleteMode,
				deletedBy, legalHoldReason, version, createdAt, updatedAt);
	}
}
