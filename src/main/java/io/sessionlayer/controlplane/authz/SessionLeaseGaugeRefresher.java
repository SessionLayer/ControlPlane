package io.sessionlayer.controlplane.authz;

import io.sessionlayer.controlplane.data.runtime.SessionLeaseRepository;
import io.sessionlayer.controlplane.observability.SloMetrics;
import java.time.Duration;
import java.time.Instant;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

@Component
public class SessionLeaseGaugeRefresher {

	private static final Logger LOG = LoggerFactory.getLogger(SessionLeaseGaugeRefresher.class);

	private final SessionLeaseRepository leases;
	private final SloMetrics metrics;

	public SessionLeaseGaugeRefresher(SessionLeaseRepository leases, SloMetrics metrics) {
		this.leases = leases;
		this.metrics = metrics;
	}

	@Scheduled(fixedDelayString = "${sessionlayer.session-limits.gauge-refresh:PT1M}", initialDelayString = "${sessionlayer.session-limits.gauge-refresh:PT1M}")
	public void refresh() {
		try {
			leases.countLive(Instant.now()).doOnNext(metrics::updateLiveLeases)
					.onErrorResume(error -> refreshFailed(error.toString())).block(Duration.ofSeconds(30));
		} catch (RuntimeException blockTimeout) {
			refreshFailed(blockTimeout.toString());
		}
	}

	private Mono<Long> refreshFailed(String cause) {
		metrics.recordLeaseGaugeRefreshFailed();
		LOG.warn("live-lease gauge refresh failed (gauge is now stale): {}", cause);
		return Mono.empty();
	}
}
