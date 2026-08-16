package io.sessionlayer.controlplane.otp;

import io.sessionlayer.controlplane.audit.AuditEventStore;
import io.sessionlayer.controlplane.auth.AuthProperties;
import io.sessionlayer.controlplane.auth.RateLimiter;
import io.sessionlayer.controlplane.auth.Secrets;
import io.sessionlayer.controlplane.data.config.OperatorSettingsRepository;
import io.sessionlayer.controlplane.data.runtime.Otp;
import io.sessionlayer.controlplane.data.runtime.OtpRepository;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import org.springframework.r2dbc.core.DatabaseClient;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

@Service
public class OtpService {

	private static final int MIN_TTL_SECONDS = 60;
	private static final int MAX_TTL_SECONDS = 300;

	// Both sides cast to `inet` (not the strict `cidr`), so an operator-friendly
	// host-bits CIDR (e.g. 192.168.1.5/24, which the schema stores via lenient
	// ::inet) does not throw at query time; `<<=` uses the stored masklen's network.
	private static final String CONSUME = """
			UPDATE runtime.otp SET used = true, used_at = now()
			WHERE otp_hash = :hash AND used = false AND expires_at > now()
			  AND (source_cidr IS NULL OR (:sourceIp <> '' AND :sourceIp::inet <<= source_cidr::inet))
			RETURNING identity, allowed_principals""";

	private final OtpRepository otps;
	private final OperatorSettingsRepository settings;
	private final AuditEventStore audit;
	private final RateLimiter rateLimiter;
	private final AuthProperties authProperties;
	private final DatabaseClient db;

	public OtpService(OtpRepository otps, OperatorSettingsRepository settings, AuditEventStore audit,
			RateLimiter rateLimiter, AuthProperties authProperties, DatabaseClient db) {
		this.otps = otps;
		this.settings = settings;
		this.audit = audit;
		this.rateLimiter = rateLimiter;
		this.authProperties = authProperties;
		this.db = db;
	}

	public record IssuedOtp(java.util.UUID id, String otp, Instant expiresAt) {
	}

	public record Resolved(String identity, List<String> principals) {
	}

	public Mono<IssuedOtp> issue(String identity, List<String> allowedPrincipals, String sourceCidr, Integer ttlSeconds,
			String actor) {
		if (identity == null || identity.isBlank() || allowedPrincipals == null || allowedPrincipals.isEmpty()) {
			return Mono.error(new IllegalArgumentException("identity and at least one principal are required"));
		}
		return defaultTtlSeconds().map(defaultTtl -> clamp(ttlSeconds == null ? defaultTtl : ttlSeconds))
				.flatMap(ttl -> {
					String raw = Secrets.randomBase32(authProperties.getOtpEntropyBytes());
					Instant expiresAt = Instant.now().plus(Duration.ofSeconds(ttl));
					Otp otp = Otp.create(Secrets.sha256Hex(raw), identity, allowedPrincipals, sourceCidr, expiresAt);
					return otps.save(otp)
							.flatMap(
									saved -> audit
											.record(actor, identity, "otp.issue", "success", null, null,
													Map.of("otp_id", saved.id().toString(), "ttl_seconds",
															String.valueOf(ttl)))
											.thenReturn(new IssuedOtp(saved.id(), raw, expiresAt)));
				});
	}

	public Mono<Resolved> validate(String presentedOtp, String sourceIp) {
		String ip = sourceIp == null ? "" : sourceIp;
		return rateLimiter.tryAcquire("otp:verify:" + ip, authProperties.getOtpVerify()).flatMap(allowed -> {
			if (!allowed) {
				return audit.record("system", null, "otp.verify", "denied", null, null,
						Map.of("reason", "rate_limited", "source_ip", ip)).then(Mono.empty());
			}
			String hash = Secrets.sha256Hex(presentedOtp == null ? "" : presentedOtp);
			return db.sql(CONSUME).bind("hash", hash).bind("sourceIp", ip)
					.map((row, meta) -> new Resolved(row.get("identity", String.class),
							listOf(row.get("allowed_principals", String[].class))))
					.one()
					.flatMap(resolved -> audit
							.record(resolved.identity(), null, "otp.verify", "success", null, null, Map.of())
							.thenReturn(resolved))
					.switchIfEmpty(audit.record("system", null, "otp.verify", "denied", null, null,
							Map.of("reason", "invalid_or_expired", "source_ip", ip)).then(Mono.empty()))
					.onErrorResume(err -> audit.record("system", null, "otp.verify", "error", null, null,
							Map.of("reason", "evaluation_error", "source_ip", ip)).then(Mono.empty()));
		});
	}

	private Mono<Integer> defaultTtlSeconds() {
		return settings.findSingleton().map(s -> s.otpTtlSeconds()).defaultIfEmpty(120);
	}

	private static int clamp(int ttl) {
		return Math.max(MIN_TTL_SECONDS, Math.min(MAX_TTL_SECONDS, ttl));
	}

	private static List<String> listOf(String[] arr) {
		return arr == null ? List.of() : List.of(arr);
	}
}
