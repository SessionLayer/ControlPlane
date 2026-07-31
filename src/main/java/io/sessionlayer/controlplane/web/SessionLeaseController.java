package io.sessionlayer.controlplane.web;

import io.sessionlayer.controlplane.api.SessionLeasesApi;
import io.sessionlayer.controlplane.api.model.ReleaseSessionLeaseRequest;
import io.sessionlayer.controlplane.api.model.SessionLeasePage;
import io.sessionlayer.controlplane.api.model.SessionLeaseResource;
import io.sessionlayer.controlplane.configapi.IdempotencyService;
import io.sessionlayer.controlplane.configapi.SessionLeaseAdminService;
import io.sessionlayer.controlplane.data.runtime.SessionLease;
import io.sessionlayer.controlplane.platform.PlatformPermissions;
import java.time.Instant;
import java.util.UUID;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

/**
 * FR-SESS-3 concurrency leases: diagnosis (`audit:read`, as for
 * {@code /v1/sessions}) and single-lease release (`lock:write`, as for a
 * session terminate — both correct live enforcement state). No bulk or
 * by-identity release exists here or below; that shape is the one this endpoint
 * refuses to make convenient.
 */
@RestController
public class SessionLeaseController implements SessionLeasesApi {

	private final SessionLeaseAdminService leases;
	private final PlatformAccess access;
	private final IdempotencyService idempotency;

	public SessionLeaseController(SessionLeaseAdminService leases, PlatformAccess access,
			IdempotencyService idempotency) {
		this.leases = leases;
		this.access = access;
		this.idempotency = idempotency;
	}

	@Override
	public Mono<ResponseEntity<SessionLeasePage>> listSessionLeases(String cursor, Integer limit, String identity,
			Boolean activeOnly, ServerWebExchange exchange) {
		return access.withPermission(PlatformPermissions.AUDIT_READ,
				subject -> leases.list(cursor, limit, identity, activeOnly).map(page -> {
					Instant now = Instant.now();
					return ResponseEntity.ok(
							new SessionLeasePage(page.items().stream().map(lease -> toResource(lease, now)).toList())
									.nextCursor(page.nextCursor()));
				}));
	}

	@Override
	public Mono<ResponseEntity<SessionLeaseResource>> getSessionLease(UUID sessionLeaseId, ServerWebExchange exchange) {
		return access.withPermission(PlatformPermissions.AUDIT_READ, subject -> leases.get(sessionLeaseId)
				.map(lease -> ResponseEntity.ok(toResource(lease, Instant.now()))));
	}

	@Override
	public Mono<ResponseEntity<SessionLeaseResource>> releaseSessionLease(UUID sessionLeaseId,
			Mono<ReleaseSessionLeaseRequest> releaseSessionLeaseRequest, String idempotencyKey,
			ServerWebExchange exchange) {
		return releaseSessionLeaseRequest
				.flatMap(req -> access.withPermission(PlatformPermissions.LOCK_WRITE, subject -> {
					Mono<ResponseEntity<SessionLeaseResource>> action = leases
							.release(sessionLeaseId, subject.identity(), req.getReason())
							.map(lease -> ResponseEntity.ok(toResource(lease, Instant.now())));
					return idempotency.execute(idempotencyKey, subject.identity(), ApiConversions.method(exchange),
							ApiConversions.path(exchange), req, SessionLeaseResource.class, action);
				}));
	}

	private static SessionLeaseResource toResource(SessionLease lease, Instant now) {
		SessionLeaseResource resource = new SessionLeaseResource(lease.id(), lease.identity(),
				ApiConversions.toOffset(lease.acquiredAt()), SessionLeaseAdminService.countsTowardCap(lease, now));
		resource.setSessionId(lease.sessionId());
		resource.setGatewayName(lease.gatewayName());
		resource.setExpiresAt(ApiConversions.toOffset(lease.expiresAt()));
		resource.setReleasedAt(ApiConversions.toOffset(lease.releasedAt()));
		return resource;
	}
}
