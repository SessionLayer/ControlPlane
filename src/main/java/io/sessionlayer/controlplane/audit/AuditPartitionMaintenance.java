package io.sessionlayer.controlplane.audit;

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

/**
 * Create-ahead maintenance for audit_event range partitions. Ensures DEFAULT
 * partition stays empty and prunable ranges land in dated partitions. Failures
 * are logged, not fatal.
 */
@Component
@ConditionalOnProperty(value = "sessionlayer.audit.partition-maintenance.enabled", havingValue = "true", matchIfMissing = true)
public class AuditPartitionMaintenance {

	private static final Logger LOG = LoggerFactory.getLogger(AuditPartitionMaintenance.class);

	/** How many months ahead to keep provisioned. */
	private static final int MONTHS_AHEAD = 6;

	private final DatabaseClient db;

	public AuditPartitionMaintenance(DatabaseClient db) {
		this.db = db;
	}

	// Fire-and-forget: NEVER block; a wedged create-ahead query must not abort CP
	// boot (would crash-loop CP and take auth down — the same shape already
	// fixed once in RecordingRetentionJob).
	@EventListener(ApplicationReadyEvent.class)
	public void ensureOnStartup() {
		ensureAhead("startup").subscribe(v -> {
		}, error -> LOG.warn("startup audit partition create-ahead failed (will retry on the schedule)", error));
	}

	/**
	 * Monthly (03:00 on the 1st by default); the cron never fires during a short
	 * test.
	 */
	@Scheduled(cron = "${sessionlayer.audit.partition-maintenance.cron:0 0 3 1 * *}")
	public void ensureMonthly() {
		ensureAhead("scheduled").block(Duration.ofSeconds(30));
	}

	private Mono<Void> ensureAhead(String trigger) {
		return db.sql("SELECT runtime.audit_ensure_partitions(date_trunc('month', now())::date, :n)")
				.bind("n", MONTHS_AHEAD).fetch().one()
				.doOnSuccess(
						r -> LOG.info("audit partition create-ahead ({}) ensured {} months", trigger, MONTHS_AHEAD))
				.onErrorResume(e -> {
					LOG.warn("audit partition create-ahead ({}) failed; the DEFAULT partition still accepts inserts",
							trigger, e);
					return Mono.empty();
				}).then();
	}
}
