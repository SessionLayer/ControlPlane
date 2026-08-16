package io.sessionlayer.controlplane.configapi;

import io.sessionlayer.controlplane.audit.AuditEventStore;
import io.sessionlayer.controlplane.authz.SessionLimitProperties;
import io.sessionlayer.controlplane.data.config.OperatorSettings;
import io.sessionlayer.controlplane.data.config.OperatorSettingsRepository;
import io.sessionlayer.controlplane.recording.CustomerPublicKeys;
import io.sessionlayer.controlplane.recording.SubmittedRecordingKey;
import io.sessionlayer.controlplane.web.ApiProblemException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import org.springframework.dao.OptimisticLockingFailureException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.reactive.TransactionalOperator;
import reactor.core.publisher.Mono;

@Service
public class OperatorSettingsConfigService {

	private static final String ORIGIN_API = "api";

	private static final String SEAL_ALGORITHM_ECIES_P256 = "ecies_p256";
	private static final int MAX_KEY_BYTES = 8 * 1024;
	private static final String OWNER_ONLY = "This direction destroys evidence and is deliberately not reachable "
			+ "through the API at any scope; it remains a database-owner operation.";

	static final String FIELD_MAX_SESSION_SECONDS = "defaultMaxSessionSeconds";
	static final String FIELD_IDLE_TIMEOUT_SECONDS = "defaultIdleTimeoutSeconds";
	static final String FIELD_MAX_CONCURRENT_SESSIONS = "defaultMaxConcurrentSessions";

	private final OperatorSettingsRepository settings;
	private final SessionLimitProperties sessionLimits;
	private final AuditEventStore audit;
	private final TransactionalOperator tx;

	public OperatorSettingsConfigService(OperatorSettingsRepository settings, SessionLimitProperties sessionLimits,
			AuditEventStore audit, TransactionalOperator tx) {
		this.settings = settings;
		this.sessionLimits = sessionLimits;
		this.audit = audit;
		this.tx = tx;
	}

	public record SettingsAudit(int auditRetentionDays, int recordingRetentionDays, String defaultWormMode,
			int otpTtlSeconds, Integer defaultMaxSessionSeconds, Integer defaultIdleTimeoutSeconds,
			Integer defaultMaxConcurrentSessions) {

		static SettingsAudit of(OperatorSettings s) {
			return new SettingsAudit(s.auditRetentionDays(), s.recordingRetentionDays(), s.defaultWormMode(),
					s.otpTtlSeconds(), s.defaultMaxSessionSeconds(), s.defaultIdleTimeoutSeconds(),
					s.defaultMaxConcurrentSessions());
		}
	}

	public record RecordingKeyAudit(String fingerprintSha256, String sealAlgorithm, String keyRef) {

		static RecordingKeyAudit of(OperatorSettings s) {
			byte[] der = s.recordingCustomerPublicKey();
			return der == null || der.length == 0
					? null
					: new RecordingKeyAudit(SubmittedRecordingKey.fingerprintSha256(der), s.recordingKeySealAlgorithm(),
							s.recordingKeyRef());
		}
	}

	public Mono<OperatorSettings> get() {
		return settings.findSingleton().switchIfEmpty(Mono.error(ApiProblemException
				.conflict("the operator-settings singleton does not exist yet; it is written at cold start")));
	}

	/**
	 * Which session-limit defaults a deployment property pins right now. Computed
	 * per request from this Control Plane's configuration, never stored — the same
	 * database serves nodes whose properties differ.
	 */
	public List<String> deploymentManagedFields() {
		List<String> pinned = new ArrayList<>(3);
		if (sessionLimits.getDefaultMaxSessionSeconds() != null) {
			pinned.add(FIELD_MAX_SESSION_SECONDS);
		}
		if (sessionLimits.getDefaultIdleTimeoutSeconds() != null) {
			pinned.add(FIELD_IDLE_TIMEOUT_SECONDS);
		}
		if (sessionLimits.getDefaultMaxConcurrent() != null) {
			pinned.add(FIELD_MAX_CONCURRENT_SESSIONS);
		}
		return List.copyOf(pinned);
	}

	public Mono<OperatorSettings> update(String actor, Long expectedVersion, int auditRetentionDays,
			int recordingRetentionDays, String defaultWormMode, int otpTtlSeconds, Integer defaultMaxSessionSeconds,
			Integer defaultIdleTimeoutSeconds, Integer defaultMaxConcurrentSessions) {
		return get().flatMap(current -> {
			requireVersion(expectedVersion, current.version());
			requireInRange(otpTtlSeconds);
			requireNoRetentionDecrease("auditRetentionDays", auditRetentionDays, current.auditRetentionDays());
			requireNoRetentionDecrease("recordingRetentionDays", recordingRetentionDays,
					current.recordingRetentionDays());
			requireWormNotWeakened(defaultWormMode, current.defaultWormMode());
			requireUnpinned(FIELD_MAX_SESSION_SECONDS, "sessionlayer.session-limits.default-max-session-seconds",
					sessionLimits.getDefaultMaxSessionSeconds(), defaultMaxSessionSeconds,
					current.defaultMaxSessionSeconds());
			requireUnpinned(FIELD_IDLE_TIMEOUT_SECONDS, "sessionlayer.session-limits.default-idle-timeout-seconds",
					sessionLimits.getDefaultIdleTimeoutSeconds(), defaultIdleTimeoutSeconds,
					current.defaultIdleTimeoutSeconds());
			requireUnpinned(FIELD_MAX_CONCURRENT_SESSIONS, "sessionlayer.session-limits.default-max-concurrent",
					sessionLimits.getDefaultMaxConcurrent(), defaultMaxConcurrentSessions,
					current.defaultMaxConcurrentSessions());

			OperatorSettings updated = current.withOperatorManaged(auditRetentionDays, recordingRetentionDays,
					defaultWormMode, otpTtlSeconds, defaultMaxSessionSeconds, defaultIdleTimeoutSeconds,
					defaultMaxConcurrentSessions, ORIGIN_API);
			return persist(updated, actor, "operator_settings.update", Map.of(), SettingsAudit.of(current),
					SettingsAudit.of(updated));
		});
	}

	public Mono<OperatorSettings> setRecordingKey(String actor, Long expectedVersion, String publicKeyBase64,
			String sealAlgorithm, String keyRef, String expectedFingerprintSha256,
			Boolean acknowledgeExistingRecordingsUndecryptable) {
		byte[] der = decodePublicKey(publicKeyBase64);
		if (SEAL_ALGORITHM_ECIES_P256.equals(sealAlgorithm)) {
			if (!CustomerPublicKeys.isValid(der, sealAlgorithm)) {
				throw ApiProblemException.validation("the submitted key is not a public key on the P-256 curve"
						+ " (secp256k1 and brainpoolP256r1 share its 256-bit field but the data plane cannot seal"
						+ " to them)");
			}
		} else {
			throw ApiProblemException.validation("sealAlgorithm '" + sealAlgorithm
					+ "' is not implemented by the data plane: the Gateway seals with ECIES on P-256 only, so a key"
					+ " stored under any other algorithm would refuse every session at the first recording. Use '"
					+ SEAL_ALGORITHM_ECIES_P256 + "'.");
		}
		requireReferenceOnly(keyRef);

		return get().flatMap(current -> {
			requireVersion(expectedVersion, current.version());
			RecordingKeyAudit before = RecordingKeyAudit.of(current);
			boolean rotation = before != null;
			requireRotationGuards(rotation, before, expectedFingerprintSha256,
					acknowledgeExistingRecordingsUndecryptable);

			OperatorSettings updated = current.withRecordingKey(der, sealAlgorithm, keyRef, ORIGIN_API);
			String action = rotation
					? "operator_settings.recording_key.rotate"
					: "operator_settings.recording_key.provision";
			return persist(updated, actor, action, Map.of("seal_algorithm", sealAlgorithm), before,
					RecordingKeyAudit.of(updated));
		});
	}

	private Mono<OperatorSettings> persist(OperatorSettings updated, String actor, String action,
			Map<String, String> detail, Object before, Object after) {
		Mono<OperatorSettings> body = settings.save(updated).flatMap(saved -> audit
				.recordChange(actor, "operator_settings", action, detail, before, after).thenReturn(saved));
		return tx.transactional(body).onErrorMap(OptimisticLockingFailureException.class, stale -> ApiProblemException
				.conflict("the operator settings were modified concurrently (stale version)"));
	}

	private static byte[] decodePublicKey(String submitted) {
		if (submitted == null || submitted.isBlank()) {
			throw ApiProblemException.validation("publicKey must be a non-empty base64 DER SubjectPublicKeyInfo");
		}
		// A pasted PEM is caught on the raw text: it does not survive base64 decoding,
		// so a check only on the decoded bytes would report "not base64" instead.
		if (SubmittedRecordingKey.carriesPemMarker(submitted)) {
			throw ApiProblemException.validation(privateKeySubmitted("PEM text"));
		}
		byte[] der;
		try {
			der = Base64.getDecoder().decode(submitted.trim());
		} catch (IllegalArgumentException notBase64) {
			throw ApiProblemException.validation("publicKey must be base64-encoded DER SubjectPublicKeyInfo");
		}
		if (der.length == 0) {
			throw ApiProblemException.validation("publicKey must be a non-empty base64 DER SubjectPublicKeyInfo");
		}
		if (der.length > MAX_KEY_BYTES) {
			throw ApiProblemException.validation("publicKey must decode to at most " + MAX_KEY_BYTES + " bytes");
		}
		if (SubmittedRecordingKey.carriesPemMarker(der)) {
			throw ApiProblemException.validation(privateKeySubmitted("PEM text"));
		}
		if (SubmittedRecordingKey.isPrivateKeyMaterial(der)) {
			throw ApiProblemException.validation(privateKeySubmitted("a private key structure"));
		}
		return der;
	}

	private static String privateKeySubmitted(String what) {
		return "publicKey carries " + what + ": private key material was submitted. Only the PUBLIC half is ever "
				+ "stored — the platform must not be able to decrypt its own recordings. Submit the base64 DER "
				+ "SubjectPublicKeyInfo of the public key and keep the private half offline.";
	}

	private static void requireReferenceOnly(String keyRef) {
		if (keyRef != null && SubmittedRecordingKey.carriesPemMarker(keyRef)) {
			throw ApiProblemException
					.validation("keyRef is a reference to where the private half is held, never key material");
		}
	}

	private static void requireRotationGuards(boolean rotation, RecordingKeyAudit before, String expectedFingerprint,
			Boolean acknowledged) {
		if (!rotation) {
			if (expectedFingerprint != null || acknowledged != null) {
				throw ApiProblemException.validation(
						"no recording key is configured, so this is a first provisioning: expectedFingerprintSha256 "
								+ "and acknowledgeExistingRecordingsUndecryptable must both be omitted");
			}
			return;
		}
		if (expectedFingerprint == null || expectedFingerprint.isBlank()) {
			throw ApiProblemException.validation("a recording key is already configured, so this is a rotation: "
					+ "expectedFingerprintSha256 must echo the key being replaced");
		}
		if (!Boolean.TRUE.equals(acknowledged)) {
			throw ApiProblemException.validation("a recording key is already configured, so this is a rotation: "
					+ "acknowledgeExistingRecordingsUndecryptable must be true. Every recording sealed under the "
					+ "outgoing key stays readable only by the outgoing private key; the incoming key cannot read them.");
		}
		if (!expectedFingerprint.equalsIgnoreCase(before.fingerprintSha256())) {
			throw ApiProblemException
					.conflict("expectedFingerprintSha256 does not match the configured key; re-read the key and retry");
		}
	}

	/**
	 * A century. The ratchet makes retention one-way, so an absurd value is not
	 * merely wrong, it is unreversible through this API — and a retention far
	 * enough out overflows the timestamp when it is stamped onto a lock, which
	 * fails every recording and so refuses every session. The ceiling is the
	 * matching guard: without it the ratchet turns a typo into an outage only the
	 * database owner can undo.
	 */
	public static final int MAX_RETENTION_DAYS = 36_525;

	private static void requireNoRetentionDecrease(String field, int submitted, int stored) {
		if (submitted < stored) {
			throw ApiProblemException.validation(field + " may not be decreased through this API (stored " + stored
					+ ", submitted " + submitted + "). " + OWNER_ONLY);
		}
		if (submitted > MAX_RETENTION_DAYS) {
			throw ApiProblemException.validation(field + " may be at most " + MAX_RETENTION_DAYS + " days (submitted "
					+ submitted + "): a longer window overflows the retain-until timestamp, and "
					+ "because retention only ratchets upward this API could not take it back down again.");
		}
	}

	private static void requireWormNotWeakened(String submitted, String stored) {
		if ("compliance".equals(stored) && "governance".equals(submitted)) {
			throw ApiProblemException.validation("defaultWormMode may not move from compliance to governance through "
					+ "this API: it would make new recordings deletable instead of un-deletable. " + OWNER_ONLY);
		}
	}

	// A pinned field is rewritten from the property on every boot, so accepting a
	// change would ship a setting that reverts at the next restart. Omission is a
	// change too (it clears the column), which is why the comparison is on the
	// value and not on presence.
	private static void requireUnpinned(String field, String property, Integer pinnedValue, Integer submitted,
			Integer stored) {
		if (pinnedValue != null && !Objects.equals(submitted, stored)) {
			throw ApiProblemException.validation(field + " is pinned by the deployment property '" + property
					+ "' and is reconciled into the row on every boot, so a change here would be reverted at the next "
					+ "restart. Send it unchanged (" + stored + ") or change the property.");
		}
	}

	private static void requireInRange(int otpTtlSeconds) {
		if (otpTtlSeconds < 60 || otpTtlSeconds > 300) {
			throw ApiProblemException.validation("otpTtlSeconds must be between 60 and 300");
		}
	}

	private static void requireVersion(Long expected, Long actual) {
		if (expected == null || !expected.equals(actual)) {
			throw ApiProblemException.conflict("stale version " + expected + " (current " + actual + ")");
		}
	}
}
