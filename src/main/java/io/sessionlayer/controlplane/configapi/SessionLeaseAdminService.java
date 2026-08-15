package io.sessionlayer.controlplane.configapi;

import io.sessionlayer.controlplane.audit.AuditEventStore;
import io.sessionlayer.controlplane.audit.AuditEventStore.AuditRecord;
import io.sessionlayer.controlplane.data.runtime.SessionLease;
import io.sessionlayer.controlplane.data.runtime.SessionLeaseRepository;
import io.sessionlayer.controlplane.web.ApiProblemException;
import io.sessionlayer.controlplane.web.CursorPages;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.springframework.data.relational.core.query.Criteria;
import org.springframework.stereotype.Service;
import org.springframework.transaction.reactive.TransactionalOperator;
import reactor.core.publisher.Mono;

/**
 * Concurrency-lease diagnosis and single-lease release, replacing the
 * raw {@code SELECT}/{@code UPDATE} on {@code runtime.session_lease} the
 * disaster-recovery runbook required. A lease that outlived its session denies
 * its identity with the same generic problem as a real policy deny, so the read
 * half is what makes the two distinguishable without a database credential.
 */
@Service
public class SessionLeaseAdminService {

	public static final String ACTION_RELEASE = "session_lease.release";

	// The reason reaches the audit stream, so bound it behind the contract's
	// maxLength the way SessionManagementService bounds a terminate reason.
	private static final int MAX_REASON_LENGTH = 4096;

	private final SessionLeaseRepository leases;
	private final CursorPages cursorPages;
	private final AuditEventStore audit;
	private final TransactionalOperator tx;

	public SessionLeaseAdminService(SessionLeaseRepository leases, CursorPages cursorPages, AuditEventStore audit,
			TransactionalOperator tx) {
		this.leases = leases;
		this.cursorPages = cursorPages;
		this.audit = audit;
		this.tx = tx;
	}

	public Mono<CursorPages.Page<SessionLease>> list(String cursor, Integer limit, String identity,
			Boolean activeOnly) {
		List<Criteria> conditions = new ArrayList<>();
		if (identity != null && !identity.isBlank()) {
			conditions.add(Criteria.where("identity").is(identity));
		}
		if (activeOnly != null) {
			Instant now = Instant.now();
			conditions.add(activeOnly.booleanValue() ? counting(now) : notCounting(now));
		}
		return cursorPages.page(SessionLease.class, Criteria.from(conditions), cursor, limit, SessionLease::id);
	}

	public Mono<SessionLease> get(UUID id) {
		return leases.findById(id).switchIfEmpty(Mono.error(ApiProblemException.notFound("session lease", id)));
	}

	/**
	 * Release exactly one lease. There is no bulk or by-identity form anywhere in
	 * this service: the cap is a hard security limit, and releasing every lease for
	 * an identity trades a bounded over-count for an under-count that lets the
	 * identity exceed it for as long as its real sessions run.
	 */
	public Mono<SessionLease> release(UUID id, String actor, String reason) {
		String trimmed = reason == null ? "" : reason.strip();
		if (trimmed.isEmpty()) {
			return Mono.error(ApiProblemException.validation("reason is required"));
		}
		if (trimmed.length() > MAX_REASON_LENGTH) {
			return Mono.error(
					ApiProblemException.validation("reason must be at most " + MAX_REASON_LENGTH + " characters"));
		}
		return get(id).flatMap(lease -> {
			Mono<SessionLease> body = leases.releaseById(id, Instant.now())
					.flatMap(rows -> auditRelease(actor, lease, trimmed, rows > 0).then(get(id)));
			return tx.transactional(body);
		});
	}

	/**
	 * Whether the cap counts this lease right now — the exact predicate
	 * {@code SessionLeaseRepository.countLiveByIdentity} applies, evaluated against
	 * the same clock, so the flag can never disagree with enforcement.
	 */
	public static boolean countsTowardCap(SessionLease lease, Instant now) {
		return lease.releasedAt() == null && (lease.expiresAt() == null || lease.expiresAt().isAfter(now));
	}

	private static Criteria counting(Instant now) {
		return Criteria.where("releasedAt").isNull()
				.and(Criteria.where("expiresAt").isNull().or("expiresAt").greaterThan(now));
	}

	private static Criteria notCounting(Instant now) {
		return Criteria.where("releasedAt").isNotNull().or("expiresAt").lessThanOrEquals(now);
	}

	// Always written, even when the row was already released: the operator asked
	// for
	// a correction to enforcement state and that request is the auditable act. The
	// no-op case is distinguishable by released_by_this_call rather than by
	// absence.
	private Mono<Void> auditRelease(String actor, SessionLease lease, String reason, boolean released) {
		Map<String, String> detail = new LinkedHashMap<>();
		detail.put("identity", lease.identity());
		detail.put("reason", reason);
		detail.put("released_by_this_call", Boolean.toString(released));
		if (lease.gatewayName() != null) {
			detail.put("gateway_name", lease.gatewayName());
		}
		if (lease.expiresAt() != null) {
			detail.put("lease_expires_at", lease.expiresAt().toString());
		}
		return audit.record(AuditRecord.builder(actor, lease.identity(), ACTION_RELEASE, "success")
				.session(lease.sessionId()).detail(detail).build());
	}
}
