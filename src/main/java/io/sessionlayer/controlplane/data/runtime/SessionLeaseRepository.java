package io.sessionlayer.controlplane.data.runtime;

import java.time.Instant;
import java.util.UUID;
import org.springframework.data.r2dbc.repository.Modifying;
import org.springframework.data.r2dbc.repository.Query;
import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import reactor.core.publisher.Mono;

public interface SessionLeaseRepository extends ReactiveCrudRepository<SessionLease, UUID> {

	Mono<SessionLease> findBySessionId(UUID sessionId);

	@Query("SELECT count(*) FROM runtime.session_lease WHERE identity = :identity AND released_at IS NULL "
			+ "AND (expires_at IS NULL OR expires_at > :now)")
	Mono<Long> countLiveByIdentity(String identity, Instant now);

	@Modifying
	@Query("UPDATE runtime.session_lease SET released_at = :now WHERE session_id = :sessionId AND released_at IS NULL")
	Mono<Integer> releaseBySessionId(UUID sessionId, Instant now);

	@Modifying
	@Query("UPDATE runtime.session_lease SET expires_at = GREATEST(expires_at, :expiresAt) "
			+ "WHERE session_id = :sessionId AND released_at IS NULL")
	Mono<Integer> extendBySessionId(UUID sessionId, Instant expiresAt);

	// Unlike extendBySessionId's GREATEST (a keep-alive floor), a re-Authorize is a
	// fresh decision and its grant_expiry is authoritative in either direction —
	// SET,
	// not GREATEST. Zero rows updated means no live lease exists for the session
	// (first Authorize, or a self-heal after a reaped one); the caller then
	// acquires
	// one through the normal cap-gated path.
	@Modifying
	@Query("UPDATE runtime.session_lease SET expires_at = :expiresAt "
			+ "WHERE session_id = :sessionId AND released_at IS NULL")
	Mono<Integer> reauthorizeBySessionId(UUID sessionId, Instant expiresAt);

	@Query("SELECT count(*) FROM runtime.session_lease WHERE released_at IS NULL "
			+ "AND (expires_at IS NULL OR expires_at > :now)")
	Mono<Long> countLive(Instant now);

	/**
	 * Operator release of ONE identified lease. Guarded on released_at IS NULL, so
	 * it is idempotent and cannot corrupt the count against the reaper or an
	 * extend: whichever statement takes the row lock first stamps it and the other
	 * updates nothing. The cap counts unreleased rows rather than decrementing a
	 * counter, so a release is at worst a no-op, never a double-decrement.
	 */
	@Modifying
	@Query("UPDATE runtime.session_lease SET released_at = :now WHERE id = :id AND released_at IS NULL")
	Mono<Integer> releaseById(UUID id, Instant now);

	@Modifying
	@Query("UPDATE runtime.session_lease SET released_at = :now "
			+ "WHERE released_at IS NULL AND expires_at IS NOT NULL AND expires_at < :cutoff")
	Mono<Integer> reapExpired(Instant now, Instant cutoff);
}
