package io.sessionlayer.controlplane.breakglass;

import io.sessionlayer.controlplane.audit.AuditEventStore;
import io.sessionlayer.controlplane.auth.AuthProperties;
import io.sessionlayer.controlplane.auth.RateLimiter;
import io.sessionlayer.controlplane.auth.Secrets;
import io.sessionlayer.controlplane.data.runtime.BreakglassCredentialRepository;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.r2dbc.core.DatabaseClient;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

/**
 * The break-glass AUTHENTICATION path. Resolves an offered FIDO2
 * sk-ecdsa PUBLIC key (primary) or offline code (fallback) to an identity and
 * scoped principals, minting the single-use token. The alert fires at
 * authentication. Any failure is generic non-resolution (fail closed). The
 * offline code is a SECRET and is NEVER logged.
 */
@Service
public class BreakglassResolutionService {

	private static final Logger LOG = LoggerFactory.getLogger(BreakglassResolutionService.class);

	// Atomic mark-used: a code row is returned (and consumed) only if it is unused,
	// unrevoked, unexpired, and the source is inside its bound CIDR (deny-only). A
	// replay/expired/revoked/wrong-source code matches nothing → fail closed. The
	// ::inet casts mirror OtpService (lenient host-bits CIDR, never throws).
	private static final String CONSUME_CODE = """
			UPDATE runtime.breakglass_offline_code SET used = true, used_at = now()
			WHERE code_hash = :hash AND used = false AND revoked_at IS NULL AND expires_at > now()
			  AND (source_cidr IS NULL OR (:sourceIp <> '' AND :sourceIp::inet <<= source_cidr::inet))
			RETURNING identity, allowed_principals, node_selector::text AS node_selector""";

	private final BreakglassCredentialRepository credentials;
	private final BreakglassTokenService tokens;
	private final BreakglassSecurityAlerts alerts;
	private final RateLimiter rateLimiter;
	private final AuthProperties authProperties;
	private final AuditEventStore audit;
	private final DatabaseClient db;
	private final ObjectMapper objectMapper;

	public BreakglassResolutionService(BreakglassCredentialRepository credentials, BreakglassTokenService tokens,
			BreakglassSecurityAlerts alerts, RateLimiter rateLimiter, AuthProperties authProperties,
			AuditEventStore audit, DatabaseClient db, ObjectMapper objectMapper) {
		this.credentials = credentials;
		this.tokens = tokens;
		this.alerts = alerts;
		this.rateLimiter = rateLimiter;
		this.authProperties = authProperties;
		this.audit = audit;
		this.db = db;
		this.objectMapper = objectMapper;
	}

	public record Resolution(String identity, List<String> principals, String token) {
	}

	public Mono<Resolution> resolveKey(byte[] skBlob, String sourceIp, UUID nodeId, UUID callerGatewayId) {
		String fingerprint;
		try {
			fingerprint = SkEcdsaPublicKey.parse(skBlob).fingerprint();
		} catch (RuntimeException malformed) {
			return denied("malformed_key", sourceIp);
		}
		Instant now = Instant.now();
		return credentials.findByKeyFingerprint(fingerprint).flatMap(cred -> {
			if (!cred.active(now) || !BreakglassNodeScope.permits(cred.nodeSelector(), nodeId)) {
				return denied("credential_unusable", sourceIp);
			}
			return mint(cred.identity(), cred.allowedPrincipals(), nodeId, sourceIp, callerGatewayId, "fido2");
		}).switchIfEmpty(denied("no_credential", sourceIp));
	}

	public Mono<Resolution> resolveCode(String code, String sourceIp, UUID nodeId, UUID callerGatewayId) {
		String ip = sourceIp == null ? "" : sourceIp;
		return rateLimiter.tryAcquire("breakglass:code:" + ip, authProperties.getOtpVerify()).flatMap(allowed -> {
			if (!allowed) {
				return denied("rate_limited", ip);
			}
			String hash = Secrets.sha256Hex(code == null ? "" : code);
			return db.sql(CONSUME_CODE).bind("hash", hash).bind("sourceIp", ip)
					.map((row, meta) -> new ConsumedCode(row.get("identity", String.class),
							listOf(row.get("allowed_principals", String[].class)),
							row.get("node_selector", String.class)))
					.one().flatMap(consumed -> {
						// The code is spent (atomic); a wrong node scope now fails closed but the
						// single-use code is not reusable — an emergency operator targets the node.
						if (!BreakglassNodeScope.permits(parse(consumed.nodeSelector()), nodeId)) {
							return denied("node_scope", ip);
						}
						return mint(consumed.identity(), consumed.principals(), nodeId, ip, callerGatewayId,
								"offline_code");
					}).switchIfEmpty(denied("invalid_or_used", ip))
					// A malformed source (bad ::inet) or any DB error → fail closed.
					.onErrorResume(err -> denied("evaluation_error", ip));
		});
	}

	private record ConsumedCode(String identity, List<String> principals, String nodeSelector) {
	}

	private Mono<Resolution> mint(String identity, List<String> principals, UUID nodeId, String sourceIp,
			UUID callerGatewayId, String method) {
		String source = (sourceIp == null || sourceIp.isBlank()) ? null : sourceIp;
		// Fire the high-priority alert AT AUTHENTICATION so a break-glass use always
		// alerts even if no session follows; the activation at Authorize is
		// the durable review record and does not re-alert.
		return tokens.mint(callerGatewayId, identity, nodeId, principals, source)
				.flatMap(token -> alerts.authenticated(identity, nodeId, source, method)
						.then(audit.record(identity, null, "breakglass.resolve", "success", null, nodeId,
								Map.of("method", method, "gateway_id", String.valueOf(callerGatewayId))))
						.thenReturn(new Resolution(identity, principals == null ? List.of() : principals, token)));
	}

	private Mono<Resolution> denied(String reason, String sourceIp) {
		// Generic non-resolution: the reason stays server-side (never the code/key).
		return audit.record("system", null, "breakglass.resolve", "denied", null, null,
				Map.of("reason", reason, "source_ip", sourceIp == null ? "" : sourceIp)).then(Mono.empty());
	}

	private JsonNode parse(String json) {
		if (json == null || json.isBlank()) {
			return null;
		}
		try {
			return objectMapper.readTree(json);
		} catch (RuntimeException malformed) {
			LOG.warn("break-glass code node_selector unparseable, failing closed (permits nothing)");
			// A non-empty selector whose node_ids permits no node → fail closed.
			return objectMapper.createObjectNode().set("node_ids", objectMapper.createArrayNode());
		}
	}

	private static List<String> listOf(String[] arr) {
		return arr == null ? List.of() : List.of(arr);
	}
}
