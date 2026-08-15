package io.sessionlayer.controlplane.observability;

import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.Gauge;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Timer;
import io.sessionlayer.controlplane.authz.ConnectDecision;
import io.sessionlayer.controlplane.data.runtime.JitRequest;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

/**
 * SLO instruments and the session-limit/lease lifecycle meters; tagged by
 * outcome/kind only.
 */
@Component
public class SloMetrics {

	static final String ESTABLISHMENT = "sessionlayer.session.establishment";
	static final String CERT_SIGN = "sessionlayer.cert.sign";
	static final String CA_SIGNER = "sessionlayer.ca.signer";
	static final String SESSION_LIMIT = "sessionlayer.session.limit";
	static final String LEASE_REAPED = "sessionlayer.session.lease.reaped";
	static final String LEASE_LIVE = "sessionlayer.session.lease.live";
	static final String LEASE_GAUGE_REFRESH_FAILED = "sessionlayer.session.lease.live.refresh.failed";
	static final String SESSION_LIFECYCLE = "sessionlayer.session.lifecycle";
	static final String JIT_LOOKUP = "sessionlayer.jit.lookup";

	static final String TAG_RPC = "rpc";
	public static final String RPC_NOTIFY_SESSION_END = "notify_session_end";
	public static final String RPC_EXTEND_SESSION_LEASE = "extend_session_lease";

	static final String TAG_OUTCOME = "outcome";
	static final String TAG_ACCESS_MODEL = "access_model";
	static final String TAG_KIND = "kind";
	// The CA-availability SLI population: a real cert-sign REQUEST vs the periodic
	// health PROBE. Kept distinct so the 99.9% target is computed over real
	// requests (the ~6/min probe baseline would otherwise mask partial
	// degradation).
	static final String TAG_SOURCE = "source";
	public static final String SOURCE_REQUEST = "request";
	public static final String SOURCE_PROBE = "probe";

	static final String OUTCOME_AVAILABLE = "available";
	static final String OUTCOME_UNAVAILABLE = "unavailable";
	static final String OUTCOME_ERROR = "error";

	private final MeterRegistry registry;
	private final AtomicLong liveLeases = new AtomicLong();

	public SloMetrics(MeterRegistry registry) {
		this.registry = registry;
		Gauge.builder(LEASE_LIVE, liveLeases, AtomicLong::doubleValue)
				.description("Live (unreleased, unexpired) concurrency leases, fleet-wide").register(registry);
	}

	public void recordSessionLimitDenied(String accessModel) {
		Counter.builder(SESSION_LIMIT).tag(TAG_OUTCOME, "denied").tag(TAG_ACCESS_MODEL, accessModel).register(registry)
				.increment();
	}

	public void recordLeasesReaped(long reaped) {
		if (reaped > 0) {
			Counter.builder(LEASE_REAPED).register(registry).increment(reaped);
		}
	}

	public void updateLiveLeases(long count) {
		liveLeases.set(count);
	}

	public void recordLeaseGaugeRefreshFailed() {
		Counter.builder(LEASE_GAUGE_REFRESH_FAILED).register(registry).increment();
	}

	public void recordSessionLifecycle(String rpc, String outcome) {
		Counter.builder(SESSION_LIFECYCLE).tag(TAG_RPC, rpc).tag(TAG_OUTCOME, outcome).register(registry).increment();
	}

	public Mono<ConnectDecision> timeEstablishment(Mono<ConnectDecision> source) {
		return Mono.defer(() -> {
			long start = System.nanoTime();
			return source
					.doOnNext(decision -> recordEstablishment(start, decision.allowed() ? "allow" : "deny",
							modelOf(decision)))
					.doOnError(error -> recordEstablishment(start, OUTCOME_ERROR, "none"))
					.doOnCancel(() -> recordEstablishment(start, "cancelled", "none"));
		});
	}

	public <T> Mono<T> timeCertSign(String kind, Mono<T> source) {
		return Mono.defer(() -> {
			long start = System.nanoTime();
			return source.doOnNext(value -> recordCertSign(start, kind, "success"))
					.doOnError(error -> recordCertSign(start, kind, OUTCOME_ERROR))
					.doOnCancel(() -> recordCertSign(start, kind, "cancelled"));
		});
	}

	/**
	 * Time the JIT grant lookup; cancelled indicates lookup-timeout (distinguished
	 * from miss).
	 */
	public Mono<JitRequest> timeJitLookup(Mono<JitRequest> source) {
		return Mono.defer(() -> {
			long start = System.nanoTime();
			return source.doOnSuccess(grant -> recordJitLookup(start, grant != null ? "hit" : "miss"))
					.doOnError(error -> recordJitLookup(start, OUTCOME_ERROR))
					.doOnCancel(() -> recordJitLookup(start, "cancelled"));
		});
	}

	private void recordJitLookup(long startNanos, String outcome) {
		Timer.builder(JIT_LOOKUP).tag(TAG_OUTCOME, outcome).register(registry).record(System.nanoTime() - startNanos,
				TimeUnit.NANOSECONDS);
	}

	public void recordSignerOutcome(String kind, String source, String outcome) {
		Counter.builder(CA_SIGNER).tag(TAG_KIND, kind).tag(TAG_SOURCE, source).tag(TAG_OUTCOME, outcome)
				.register(registry).increment();
	}

	private void recordEstablishment(long startNanos, String outcome, String accessModel) {
		Timer.builder(ESTABLISHMENT).tag(TAG_OUTCOME, outcome).tag(TAG_ACCESS_MODEL, accessModel).register(registry)
				.record(System.nanoTime() - startNanos, TimeUnit.NANOSECONDS);
	}

	private void recordCertSign(long startNanos, String kind, String outcome) {
		Timer.builder(CERT_SIGN).tag(TAG_KIND, kind).tag(TAG_OUTCOME, outcome).register(registry)
				.record(System.nanoTime() - startNanos, TimeUnit.NANOSECONDS);
	}

	private static String modelOf(ConnectDecision decision) {
		if (decision.trace() != null && decision.trace().accessModel() != null) {
			return decision.trace().accessModel();
		}
		return decision.allowed() ? "standing" : "none";
	}
}
