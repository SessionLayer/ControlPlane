package io.sessionlayer.controlplane.audit;

import io.sessionlayer.controlplane.data.runtime.AuditEvent;
import java.util.List;

/**
 * Verifies the audit_event hash chain (FR-AUD-3): record_hash =
 * SHA-256(prev_hash || canonical(event)). Proves no row was altered, removed,
 * or reordered (WORM baseline in §12.2; tail truncation is SPEC-DEFERRED,
 * FR-AUD-10).
 */
public final class AuditChainVerifier {

	private AuditChainVerifier() {
	}

	public record Result(boolean valid, String failure) {

		static Result ok() {
			return new Result(true, null);
		}

		static Result broken(String failure) {
			return new Result(false, failure);
		}
	}

	public static Result verify(List<AuditEvent> chainInSeqOrder) {
		String expectedPrev = AuditRecordHash.GENESIS;
		long prevSeq = Long.MIN_VALUE;
		for (AuditEvent event : chainInSeqOrder) {
			if (event.recordHash() == null || event.prevHash() == null) {
				return Result.broken("unchained row in chain: " + event.id());
			}
			if (event.seq() != null) {
				if (event.seq() <= prevSeq) {
					return Result.broken("seq not strictly increasing at " + event.id());
				}
				prevSeq = event.seq();
			}
			if (!expectedPrev.equals(event.prevHash())) {
				return Result.broken("prev_hash link broken at " + event.id());
			}
			if (!AuditRecordHash.recordHash(event.prevHash(), event).equals(event.recordHash())) {
				return Result.broken("record_hash mismatch at " + event.id());
			}
			expectedPrev = event.recordHash();
		}
		return Result.ok();
	}
}
