package io.sessionlayer.controlplane.web;

import io.sessionlayer.controlplane.api.GatewayEnrollmentTokensApi;
import io.sessionlayer.controlplane.api.model.GatewayEnrollmentTokenList;
import io.sessionlayer.controlplane.api.model.GatewayEnrollmentTokenResource;
import io.sessionlayer.controlplane.api.model.IssueGatewayEnrollmentTokenRequest;
import io.sessionlayer.controlplane.api.model.IssuedGatewayEnrollmentToken;
import io.sessionlayer.controlplane.audit.AuditEventStore;
import io.sessionlayer.controlplane.data.runtime.GatewayEnrollmentToken;
import io.sessionlayer.controlplane.gateway.GatewayEnrollmentTokenService;
import io.sessionlayer.controlplane.gateway.GatewayNames;
import io.sessionlayer.controlplane.mtls.MtlsProperties;
import io.sessionlayer.controlplane.platform.PlatformPermissions;
import java.time.Duration;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.Map;
import java.util.UUID;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.transaction.reactive.TransactionalOperator;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

/**
 * Gateway enrollment tokens (RBAC + audited). Replaces the raw {@code INSERT
 * INTO runtime.gateway_enrollment_token} the install guide required, so
 * installing a Gateway no longer needs a database credential the hardening
 * guide tells the operator to lock away (Design §4.B; FR-JOIN-3). The raw token
 * is returned once at issuance and never again.
 */
@RestController
public class GatewayEnrollmentTokenController implements GatewayEnrollmentTokensApi {

	private final GatewayEnrollmentTokenService enrollmentTokens;
	private final MtlsProperties properties;
	private final AuditEventStore audit;
	private final PlatformAccess access;
	private final TransactionalOperator tx;

	public GatewayEnrollmentTokenController(GatewayEnrollmentTokenService enrollmentTokens, MtlsProperties properties,
			AuditEventStore audit, PlatformAccess access, TransactionalOperator tx) {
		this.enrollmentTokens = enrollmentTokens;
		this.properties = properties;
		this.audit = audit;
		this.access = access;
		this.tx = tx;
	}

	@Override
	public Mono<ResponseEntity<IssuedGatewayEnrollmentToken>> issueGatewayEnrollmentToken(
			Mono<IssueGatewayEnrollmentTokenRequest> issueGatewayEnrollmentTokenRequest, ServerWebExchange exchange) {
		return issueGatewayEnrollmentTokenRequest
				.flatMap(req -> access.withPermission(PlatformPermissions.GATEWAY_ENROLL, subject -> {
					String gatewayName = req.getGatewayName();
					// Validate before minting: the name scopes the token and later becomes the
					// identity CN/SAN, so a bad name is a 400, never a persisted token. A name
					// equal to one of the CP's own hostnames would yield a CA-signed serverAuth
					// leaf for the Control Plane itself, so it is refused here too.
					if (!GatewayNames.isEnrollable(gatewayName, properties.getServer().getHostnames())) {
						return Mono.error(ApiProblemException.malformed("invalid gatewayName"));
					}
					Duration ttl = clampTtl(req.getTtlSeconds());
					// Persist + audit atomically so a mint that cannot be audited never stands.
					Mono<GatewayEnrollmentTokenService.MintedEnrollmentToken> minted = tx.transactional(enrollmentTokens
							.mint(gatewayName, subject.identity(), ttl)
							.flatMap(token -> audit
									.record(subject.identity(), token.id().toString(), "gateway_enrollment_token.issue",
											"success", null, null, Map.of("gateway_name", gatewayName))
									.thenReturn(token)));
					return minted.map(token -> ResponseEntity.status(HttpStatus.CREATED).body(toIssued(token)));
				}));
	}

	@Override
	public Mono<ResponseEntity<GatewayEnrollmentTokenList>> listGatewayEnrollmentTokens(ServerWebExchange exchange) {
		return access.withPermission(PlatformPermissions.GATEWAY_ENROLL,
				subject -> enrollmentTokens.listActive().map(GatewayEnrollmentTokenController::toResource).collectList()
						.map(list -> ResponseEntity.ok(new GatewayEnrollmentTokenList(list))));
	}

	@Override
	public Mono<ResponseEntity<Void>> revokeGatewayEnrollmentToken(UUID gatewayEnrollmentTokenId,
			ServerWebExchange exchange) {
		return access.withPermission(PlatformPermissions.GATEWAY_ENROLL, subject -> {
			// Idempotent: 204 whether the token is absent, live, or already consumed.
			Mono<Void> revoked = tx.transactional(enrollmentTokens.revoke(gatewayEnrollmentTokenId)
					.then(audit.record(subject.identity(), gatewayEnrollmentTokenId.toString(),
							"gateway_enrollment_token.revoke", "success", null, null, Map.of())));
			return revoked.thenReturn(ResponseEntity.noContent().<Void>build());
		});
	}

	private Duration clampTtl(Integer requestedSeconds) {
		if (requestedSeconds == null || requestedSeconds <= 0) {
			return properties.getEnrollmentTokenTtl();
		}
		Duration requested = Duration.ofSeconds(requestedSeconds);
		Duration max = properties.getEnrollmentTokenMaxTtl();
		return requested.compareTo(max) > 0 ? max : requested;
	}

	private static IssuedGatewayEnrollmentToken toIssued(GatewayEnrollmentTokenService.MintedEnrollmentToken minted) {
		return new IssuedGatewayEnrollmentToken(minted.id(), minted.rawToken(), minted.gatewayName(), Boolean.TRUE,
				toOffset(minted.expiresAt()));
	}

	private static GatewayEnrollmentTokenResource toResource(GatewayEnrollmentToken token) {
		GatewayEnrollmentTokenResource resource = new GatewayEnrollmentTokenResource(token.id(), token.gatewayName(),
				token.singleUse(), toOffset(token.expiresAt()), toOffset(token.createdAt()));
		resource.setCreatedBy(token.createdBy());
		return resource;
	}

	private static OffsetDateTime toOffset(Instant instant) {
		return instant == null ? null : instant.atOffset(ZoneOffset.UTC);
	}
}
