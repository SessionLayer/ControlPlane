package io.sessionlayer.controlplane.auth;

import java.time.Duration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.r2dbc.core.DatabaseClient;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

@Component
@ConditionalOnProperty(value = "sessionlayer.auth.maintenance.enabled", havingValue = "true", matchIfMissing = true)
public class AuthMaintenanceService {

	private static final Logger LOG = LoggerFactory.getLogger(AuthMaintenanceService.class);

	private static final String[] PRUNES = {"DELETE FROM runtime.consumed_assertion WHERE not_after < now()",
			"DELETE FROM runtime.auth_rate_limit WHERE window_start < now() - interval '1 hour'",
			"DELETE FROM runtime.oidc_login WHERE expires_at < now() - interval '1 hour'",
			"DELETE FROM runtime.device_flow WHERE expires_at < now() - interval '1 day'",
			"DELETE FROM runtime.otp WHERE expires_at < now() - interval '1 hour'",
			"DELETE FROM runtime.idempotency_key WHERE expires_at < now()"};

	private final DatabaseClient db;

	public AuthMaintenanceService(DatabaseClient db) {
		this.db = db;
	}

	// Fire-and-forget: NEVER block; a wedged startup prune must not abort CP boot
	// (would crash-loop CP and take auth down).
	@EventListener(ApplicationReadyEvent.class)
	public void pruneOnStartup() {
		prune("startup").subscribe(v -> {
		}, error -> LOG.warn("startup auth maintenance prune failed (will retry on the schedule)", error));
	}

	@Scheduled(cron = "${sessionlayer.auth.maintenance.cron:0 7 * * * *}")
	public void pruneHourly() {
		prune("scheduled").block(Duration.ofSeconds(30));
	}

	private Mono<Void> prune(String trigger) {
		Mono<Void> chain = Mono.empty();
		for (String sql : PRUNES) {
			chain = chain.then(db.sql(sql).fetch().rowsUpdated().then());
		}
		return chain.doOnSuccess(v -> LOG.debug("auth maintenance prune ({}) complete", trigger)).onErrorResume(e -> {
			LOG.warn("auth maintenance prune ({}) failed; retrying next cycle", trigger, e);
			return Mono.empty();
		});
	}
}
