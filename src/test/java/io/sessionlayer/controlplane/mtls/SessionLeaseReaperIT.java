package io.sessionlayer.controlplane.mtls;

import static org.assertj.core.api.Assertions.assertThat;

import io.micrometer.core.instrument.MeterRegistry;
import io.sessionlayer.controlplane.authz.SessionLeaseGaugeRefresher;
import io.sessionlayer.controlplane.authz.SessionLeaseReaper;
import io.sessionlayer.controlplane.data.runtime.SessionLease;
import io.sessionlayer.controlplane.data.runtime.SessionLeaseRepository;
import java.time.Instant;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

class SessionLeaseReaperIT extends AbstractMtlsIT {

	@Autowired
	private SessionLeaseRepository leases;
	@Autowired
	private SessionLeaseReaper reaper;
	@Autowired
	private SessionLeaseGaugeRefresher gaugeRefresher;
	@Autowired
	private MeterRegistry meters;

	@Test
	void theSweepReleasesLeakedExpiredLeasesAndLeavesTheRestUntouched() {
		String identity = "reap-" + UUID.randomUUID();
		// Leaked: unreleased, expired well past the default 5m grace.
		SessionLease leaked = leases.save(SessionLease.acquire(identity, null, "gw-x", Instant.now().minusSeconds(7200),
				Instant.now().minusSeconds(3600))).block();
		SessionLease live = leases
				.save(SessionLease.acquire(identity, null, "gw-y", Instant.now(), Instant.now().plusSeconds(3600)))
				.block();
		SessionLease released = leases.save(SessionLease.acquire(identity, null, "gw-z",
				Instant.now().minusSeconds(7200), Instant.now().minusSeconds(3600))).block();
		leases.save(new SessionLease(released.id(), released.identity(), released.sessionId(), released.gatewayName(),
				released.acquiredAt(), released.expiresAt(), Instant.now().minusSeconds(1800), released.version(),
				released.createdAt(), released.updatedAt())).block();
		Instant releasedAtBefore = leases.findById(released.id()).block().releasedAt();
		double reapedBefore = reapedCount();

		reaper.sweep();

		assertThat(leases.findById(leaked.id()).block().releasedAt()).isNotNull();
		assertThat(leases.findById(live.id()).block().releasedAt()).isNull();
		assertThat(leases.findById(released.id()).block().releasedAt()).isEqualTo(releasedAtBefore);

		assertThat(reapedCount()).isGreaterThanOrEqualTo(reapedBefore + 1);
	}

	// The live-lease gauge tracks the fleet-wide unreleased+unexpired count after
	// a scheduled refresh (no per-identity tag - OTEL content rule).
	@Test
	void theLiveLeaseGaugeTracksTheFleetWideCount() {
		gaugeRefresher.refresh();
		double baseline = liveGauge();

		String identity = "gauge-" + UUID.randomUUID();
		leases.save(SessionLease.acquire(identity, null, "gw-g", Instant.now(), Instant.now().plusSeconds(3600)))
				.block();
		gaugeRefresher.refresh();
		assertThat(liveGauge()).isEqualTo(baseline + 1);
	}

	private double reapedCount() {
		var counter = meters.find("sessionlayer.session.lease.reaped").counter();
		return counter == null ? 0 : counter.count();
	}

	private double liveGauge() {
		var gauge = meters.find("sessionlayer.session.lease.live").gauge();
		assertThat(gauge).isNotNull();
		return gauge.value();
	}
}
