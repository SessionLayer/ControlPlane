package io.sessionlayer.controlplane.gateway;

import io.r2dbc.spi.Row;
import io.r2dbc.spi.RowMetadata;
import io.sessionlayer.controlplane.audit.AuditEventStore;
import io.sessionlayer.controlplane.data.runtime.GatewayIdentityRepository;
import io.sessionlayer.controlplane.ha.PresenceFreshness;
import io.sessionlayer.controlplane.web.ApiProblemException;
import io.sessionlayer.controlplane.web.CursorPages;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.springframework.r2dbc.core.DatabaseClient;
import org.springframework.stereotype.Service;
import org.springframework.transaction.reactive.TransactionalOperator;
import reactor.core.publisher.Mono;

@Service
public class GatewayDirectoryService {

	public static final String ACTION_REMOVE = "gateway.remove";

	/**
	 * A removal that overrode a live Gateway - presence, open sessions, or both -
	 * is a separate action, never folded into the ordinary one: a search for "who
	 * took a live Gateway down" must not have to reconstruct that from detail
	 * fields.
	 */
	public static final String ACTION_REMOVE_FORCED = "gateway.remove_forced";

	// The disclosure boundary, written out rather than inherited from the entity:
	// mtls_identity_ref is the identity's key-material pointer and is deliberately
	// absent, so no read path here can surface it even by accident.
	private static final String COLUMNS = "id, name, fingerprint, prev_fingerprint, generation, join_method, status, "
			+ "issued_at, not_after, created_at, updated_at";

	private static final String OPEN_SESSION_COUNT = "SELECT count(*) FROM runtime.ssh_session "
			+ "WHERE gateway_id = :id AND ended_at IS NULL";

	private static final String PRESENCE_BY_OWNER = """
			SELECT owning_gateway,
			       count(*) FILTER (WHERE last_seen >= :stale_before) AS fresh_nodes,
			       max(last_seen) AS last_seen
			FROM runtime.presence
			WHERE owning_gateway = ANY(:names)
			GROUP BY owning_gateway
			""";

	private static final String FRESH_PRESENCE_COUNT = "SELECT count(*) FROM runtime.presence "
			+ "WHERE owning_gateway = :name AND last_seen >= :stale_before";

	private final GatewayIdentityRepository gatewayIdentities;
	private final DatabaseClient db;
	private final PresenceFreshness presenceFreshness;
	private final AuditEventStore audit;
	private final TransactionalOperator tx;

	public GatewayDirectoryService(GatewayIdentityRepository gatewayIdentities, DatabaseClient db,
			PresenceFreshness presenceFreshness, AuditEventStore audit, TransactionalOperator tx) {
		this.gatewayIdentities = gatewayIdentities;
		this.db = db;
		this.presenceFreshness = presenceFreshness;
		this.audit = audit;
		this.tx = tx;
	}

	public record GatewayView(UUID id, String name, String fingerprint, String prevFingerprint, long generation,
			String joinMethod, String status, Instant issuedAt, Instant notAfter, Instant createdAt, Instant updatedAt,
			int presenceNodeCount, Instant presenceLastSeenAt) {
	}

	private record Identity(UUID id, String name, String fingerprint, String prevFingerprint, long generation,
			String joinMethod, String status, Instant issuedAt, Instant notAfter, Instant createdAt,
			Instant updatedAt) {
	}

	private record PresenceSummary(int freshNodes, Instant lastSeen) {
	}

	public Mono<CursorPages.Page<GatewayView>> list(String cursor, Integer limit, String name, String status) {
		int pageSize = CursorPages.clamp(limit);
		UUID after = CursorPages.decodeCursor(cursor);
		List<String> where = new ArrayList<>();
		if (after != null) {
			where.add("id > :after");
		}
		if (name != null && !name.isBlank()) {
			where.add("name = :name");
		}
		if (status != null && !status.isBlank()) {
			where.add("status = :status");
		}
		String sql = "SELECT " + COLUMNS + " FROM runtime.gateway_identity"
				+ (where.isEmpty() ? "" : " WHERE " + String.join(" AND ", where)) + " ORDER BY id ASC LIMIT "
				+ (pageSize + 1);
		DatabaseClient.GenericExecuteSpec spec = db.sql(sql);
		if (after != null) {
			spec = spec.bind("after", after);
		}
		if (name != null && !name.isBlank()) {
			spec = spec.bind("name", name);
		}
		if (status != null && !status.isBlank()) {
			spec = spec.bind("status", status);
		}
		return spec.map(GatewayDirectoryService::toIdentity).all().collectList().flatMap(rows -> {
			boolean more = rows.size() > pageSize;
			List<Identity> items = more ? List.copyOf(rows.subList(0, pageSize)) : rows;
			String next = more ? CursorPages.encodeCursor(items.get(items.size() - 1).id()) : null;
			return presenceByOwner(items.stream().map(Identity::name).toList()).map(
					presence -> new CursorPages.Page<>(items.stream().map(row -> view(row, presence)).toList(), next));
		});
	}

	public Mono<GatewayView> get(UUID id) {
		return db.sql("SELECT " + COLUMNS + " FROM runtime.gateway_identity WHERE id = :id").bind("id", id)
				.map(GatewayDirectoryService::toIdentity).one()
				.switchIfEmpty(Mono.error(ApiProblemException.notFound("gateway", id)))
				.flatMap(row -> presenceByOwner(List.of(row.name())).map(presence -> view(row, presence)));
	}

	/**
	 * Remove one identity, freeing its name.
	 *
	 * <p>
	 * Guards on two independent kinds of liveness, because they are not the same
	 * thing and only one of them was obvious. Fresh presence means the Gateway is
	 * fronting nodes, which a removal strands. Open sessions mean the FK's
	 * {@code ON DELETE SET NULL} is about to rewrite {@code gateway_id} out from
	 * under them, and {@code RecordingRegistrationService} authorises both
	 * {@code RequestUpload} and {@code FinalizeRecording} on that exact column - so
	 * a Gateway whose heartbeat has merely lapsed while it is still bridging live
	 * traffic would pass a presence-only guard, and every in-flight recording would
	 * become unuploadable, unfinalizable, and stuck at {@code 'recording'} for
	 * ever. A forced removal therefore ends those sessions and marks their
	 * recordings failed, so the residual state says the recording was lost rather
	 * than pretending it is still being written.
	 */
	public Mono<Void> remove(UUID id, boolean force, String actor) {
		return gatewayIdentities.findById(id).switchIfEmpty(Mono.error(ApiProblemException.notFound("gateway", id)))
				.flatMap(gateway -> Mono.zip(freshPresenceCount(gateway.name()), openSessionCount(id))
						.flatMap(liveness -> {
							long present = liveness.getT1();
							long openSessions = liveness.getT2();
							if ((present > 0 || openSessions > 0) && !force) {
								return Mono.<Void>error(
										ApiProblemException.conflict(refusal(gateway.name(), present, openSessions)));
							}
							Map<String, String> detail = new LinkedHashMap<>();
							detail.put("gateway_name", gateway.name());
							detail.put("generation", Long.toString(gateway.generation()));
							detail.put("join_method", gateway.joinMethod());
							detail.put("presence_node_count", Long.toString(present));
							detail.put("open_session_count", Long.toString(openSessions));
							detail.put("force_requested", Boolean.toString(force));
							if (gateway.fingerprint() != null) {
								detail.put("fingerprint", gateway.fingerprint());
							}
							String action = present > 0 || openSessions > 0 ? ACTION_REMOVE_FORCED : ACTION_REMOVE;
							// Close the sessions BEFORE the delete, while gateway_id still
							// identifies them; afterwards the FK has nulled it and nothing can
							// find them. Delete + audit share the transaction so a removal that
							// cannot be audited never stands - the freed name is what a later
							// enrollment is judged by.
							return tx.transactional(closeStrandedSessions(id, openSessions)
									.then(gatewayIdentities.deleteById(id))
									.then(audit.record(actor, gateway.name(), action, "success", null, null, detail)));
						}));
	}

	private static String refusal(String name, long present, long openSessions) {
		StringBuilder held = new StringBuilder("gateway ").append(name).append(" is still live: ");
		held.append(present).append(" node control channel(s), ").append(openSessions).append(" open session(s). ");
		held.append("End the sessions first (POST /v1/sessions/{sessionId}/terminate) so their recordings finalize, ");
		held.append("then remove; or re-send with force=true to remove it, strand the nodes and fail the recordings");
		return held.toString();
	}

	private Mono<Void> closeStrandedSessions(UUID gatewayId, long openSessions) {
		if (openSessions == 0) {
			return Mono.empty();
		}
		// Fail the recordings FIRST, while ended_at still identifies exactly the
		// in-flight sessions. Doing it after the end-stamp would widen the subquery to
		// every session this Gateway ever ran.
		return db.sql("UPDATE runtime.recording_ref SET status = 'failed' WHERE status = 'recording' "
				+ "AND session_id IN (SELECT id FROM runtime.ssh_session WHERE gateway_id = :id AND ended_at IS NULL)")
				.bind("id", gatewayId).fetch().rowsUpdated()
				.then(db.sql("UPDATE runtime.ssh_session SET ended_at = :now, end_reason = 'gateway_removed' "
						+ "WHERE gateway_id = :id AND ended_at IS NULL").bind("now", Instant.now())
						.bind("id", gatewayId).fetch().rowsUpdated())
				.then();
	}

	private Mono<Long> freshPresenceCount(String name) {
		return db.sql(FRESH_PRESENCE_COUNT).bind("name", name).bind("stale_before", staleBefore())
				.map((row, meta) -> row.get(0, Long.class)).one().defaultIfEmpty(0L);
	}

	private Mono<Long> openSessionCount(UUID gatewayId) {
		return db.sql(OPEN_SESSION_COUNT).bind("id", gatewayId).map((row, meta) -> row.get(0, Long.class)).one()
				.defaultIfEmpty(0L);
	}

	private Mono<Map<String, PresenceSummary>> presenceByOwner(List<String> names) {
		if (names.isEmpty()) {
			return Mono.just(Map.of());
		}
		return db.sql(PRESENCE_BY_OWNER).bind("names", names.toArray(String[]::new)).bind("stale_before", staleBefore())
				.map((row, meta) -> {
					Long fresh = row.get("fresh_nodes", Long.class);
					return Map.entry(row.get("owning_gateway", String.class), new PresenceSummary(
							fresh == null ? 0 : fresh.intValue(), row.get("last_seen", Instant.class)));
				}).all().collectMap(Map.Entry::getKey, Map.Entry::getValue);
	}

	private Instant staleBefore() {
		return presenceFreshness.staleBefore(Instant.now());
	}

	private static GatewayView view(Identity row, Map<String, PresenceSummary> presence) {
		PresenceSummary summary = presence.get(row.name());
		return new GatewayView(row.id(), row.name(), row.fingerprint(), row.prevFingerprint(), row.generation(),
				row.joinMethod(), row.status(), row.issuedAt(), row.notAfter(), row.createdAt(), row.updatedAt(),
				summary == null ? 0 : summary.freshNodes(), summary == null ? null : summary.lastSeen());
	}

	private static Identity toIdentity(Row row, RowMetadata meta) {
		Long generation = row.get("generation", Long.class);
		return new Identity(row.get("id", UUID.class), row.get("name", String.class),
				row.get("fingerprint", String.class), row.get("prev_fingerprint", String.class),
				generation == null ? 0L : generation, row.get("join_method", String.class),
				row.get("status", String.class), row.get("issued_at", Instant.class),
				row.get("not_after", Instant.class), row.get("created_at", Instant.class),
				row.get("updated_at", Instant.class));
	}
}
