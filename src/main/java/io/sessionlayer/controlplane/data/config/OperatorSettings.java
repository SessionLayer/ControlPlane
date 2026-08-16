package io.sessionlayer.controlplane.data.config;

import io.sessionlayer.controlplane.data.Uuids;
import java.time.Instant;
import java.util.UUID;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.Id;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.annotation.Version;
import org.springframework.data.relational.core.mapping.Table;

@Table(schema = "config", name = "operator_settings")
public record OperatorSettings(@Id UUID id, boolean singleton, String kekReference, String defaultCaBackend,
		int auditRetentionDays, String defaultWormMode, int otpTtlSeconds, Integer defaultMaxSessionSeconds,
		Integer defaultIdleTimeoutSeconds, Integer defaultMaxConcurrentSessions, String bootstrapAdminSubject,
		String bootstrapCredentialHash, boolean bootstrapCompleted, Instant bootstrapCompletedAt,
		byte[] recordingCustomerPublicKey, String recordingKeySealAlgorithm, String recordingKeyRef,
		int recordingRetentionDays, boolean recordingStrictDefault, String origin, @Version Long version,
		@CreatedDate Instant createdAt, @LastModifiedDate Instant updatedAt) {

	/**
	 * Cold-start defaults (365d retention, governance WORM, local CA). Recording
	 * key deliberately unset until operator provisioned; BeginRecording fails
	 * closed.
	 */
	public static OperatorSettings defaults() {
		return new OperatorSettings(Uuids.v7(), true, null, "local", 365, "governance", 120, null, null, null, null,
				null, false, null, null, "ecies_p256", null, 365, true, "default", null, null, null);
	}

	public OperatorSettings withOperatorManaged(int auditRetentionDays, int recordingRetentionDays,
			String defaultWormMode, int otpTtlSeconds, Integer defaultMaxSessionSeconds,
			Integer defaultIdleTimeoutSeconds, Integer defaultMaxConcurrentSessions, String origin) {
		return new OperatorSettings(id, singleton, kekReference, defaultCaBackend, auditRetentionDays, defaultWormMode,
				otpTtlSeconds, defaultMaxSessionSeconds, defaultIdleTimeoutSeconds, defaultMaxConcurrentSessions,
				bootstrapAdminSubject, bootstrapCredentialHash, bootstrapCompleted, bootstrapCompletedAt,
				recordingCustomerPublicKey, recordingKeySealAlgorithm, recordingKeyRef, recordingRetentionDays,
				recordingStrictDefault, origin, version, createdAt, updatedAt);
	}

	public OperatorSettings withRecordingKey(byte[] recordingCustomerPublicKey, String recordingKeySealAlgorithm,
			String recordingKeyRef, String origin) {
		return new OperatorSettings(id, singleton, kekReference, defaultCaBackend, auditRetentionDays, defaultWormMode,
				otpTtlSeconds, defaultMaxSessionSeconds, defaultIdleTimeoutSeconds, defaultMaxConcurrentSessions,
				bootstrapAdminSubject, bootstrapCredentialHash, bootstrapCompleted, bootstrapCompletedAt,
				recordingCustomerPublicKey, recordingKeySealAlgorithm, recordingKeyRef, recordingRetentionDays,
				recordingStrictDefault, origin, version, createdAt, updatedAt);
	}

	public OperatorSettings withDefaultMaxConcurrentSessions(Integer defaultMaxConcurrentSessions) {
		return new OperatorSettings(id, singleton, kekReference, defaultCaBackend, auditRetentionDays, defaultWormMode,
				otpTtlSeconds, defaultMaxSessionSeconds, defaultIdleTimeoutSeconds, defaultMaxConcurrentSessions,
				bootstrapAdminSubject, bootstrapCredentialHash, bootstrapCompleted, bootstrapCompletedAt,
				recordingCustomerPublicKey, recordingKeySealAlgorithm, recordingKeyRef, recordingRetentionDays,
				recordingStrictDefault, origin, version, createdAt, updatedAt);
	}

	public OperatorSettings withDefaultMaxSessionSeconds(Integer defaultMaxSessionSeconds) {
		return new OperatorSettings(id, singleton, kekReference, defaultCaBackend, auditRetentionDays, defaultWormMode,
				otpTtlSeconds, defaultMaxSessionSeconds, defaultIdleTimeoutSeconds, defaultMaxConcurrentSessions,
				bootstrapAdminSubject, bootstrapCredentialHash, bootstrapCompleted, bootstrapCompletedAt,
				recordingCustomerPublicKey, recordingKeySealAlgorithm, recordingKeyRef, recordingRetentionDays,
				recordingStrictDefault, origin, version, createdAt, updatedAt);
	}

	public OperatorSettings withDefaultIdleTimeoutSeconds(Integer defaultIdleTimeoutSeconds) {
		return new OperatorSettings(id, singleton, kekReference, defaultCaBackend, auditRetentionDays, defaultWormMode,
				otpTtlSeconds, defaultMaxSessionSeconds, defaultIdleTimeoutSeconds, defaultMaxConcurrentSessions,
				bootstrapAdminSubject, bootstrapCredentialHash, bootstrapCompleted, bootstrapCompletedAt,
				recordingCustomerPublicKey, recordingKeySealAlgorithm, recordingKeyRef, recordingRetentionDays,
				recordingStrictDefault, origin, version, createdAt, updatedAt);
	}
}
