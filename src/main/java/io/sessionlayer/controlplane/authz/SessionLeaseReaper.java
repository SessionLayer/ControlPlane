package io.sessionlayer.controlplane.authz;

import io.sessionlayer.controlplane.data.runtime.SessionLeaseRepository;
import io.sessionlayer.controlplane.observability.SloMetrics;
import java.time.Duration;
import java.time.Instant;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

@Component
@ConditionalOnProperty(value = "sessionlayer.session-limits.reaper.enabled", havingValue = "true", matchIfMissing = true)
public class SessionLeaseReaper {

	static final Duration MIN_GRACE = Duration.ofMinutes(1);

	private static final Logger LOG = LoggerFactory.getLogger(SessionLeaseReaper.class);

	private final SessionLeaseRepository leases;
	private final SessionLimitProperties properties;
	private final SloMetrics metrics;

	public SessionLeaseReaper(SessionLeaseRepository leases, SessionLimitProperties properties, SloMetrics metrics) {
		this.leases = leases;
		this.properties = properties;
		this.metrics = metrics;
	}

	@Scheduled(fixedDelayString = "${sessionlayer.session-limits.reaper.interval:PT1H}", initialDelayString = "${sessionlayer.session-limits.reaper.interval:PT1H}")
	public void sweep() {
		Instant now = Instant.now();
		Instant cutoff = now.minus(effectiveGrace());
		try {
			leases.reapExpired(now, cutoff).doOnNext(reaped -> {
				metrics.recordLeasesReaped(reaped);
				if (reaped > 0) {
					LOG.info("session-lease reaper released {} leaked (expired, unreleased) lease(s)", reaped);
				}
			}).onErrorResume(error -> {
				LOG.warn("session-lease reaper failed (the concurrency count already ignores expired leases): {}",
						error.toString());
				return Mono.empty();
			}).block(Duration.ofSeconds(30));
		} catch (RuntimeException blockTimeout) {
			LOG.warn("session-lease reaper timed out (the concurrency count already ignores expired leases): {}",
					blockTimeout.toString());
		}
	}

	private Duration effectiveGrace() {
		Duration configured = properties.getReaper().getGrace();
		if (configured == null || configured.compareTo(MIN_GRACE) < 0) {
			LOG.warn(
					"sessionlayer.session-limits.reaper.grace={} is below the {} floor - clamping (a near-zero "
							+ "grace could reap a live RunToTtl lease between extensions and under-count)",
					configured, MIN_GRACE);
			return MIN_GRACE;
		}
		return configured;
	}
}
