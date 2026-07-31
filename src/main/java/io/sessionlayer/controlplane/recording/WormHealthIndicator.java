package io.sessionlayer.controlplane.recording;

import java.time.Duration;
import org.springframework.boot.health.autoconfigure.contributor.ConditionalOnEnabledHealthIndicator;
import org.springframework.boot.health.contributor.Health;
import org.springframework.boot.health.contributor.ReactiveHealthIndicator;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

@Component("worm")
@ConditionalOnEnabledHealthIndicator("worm")
public class WormHealthIndicator implements ReactiveHealthIndicator {

	private static final Duration CACHE_TTL = Duration.ofSeconds(10);

	private final RecordingStore worm;

	private volatile Health cached;
	private volatile long cachedUntilNanos;

	public WormHealthIndicator(RecordingStore worm) {
		this.worm = worm;
	}

	@Override
	public Mono<Health> health() {
		Health snapshot = cached;
		if (snapshot != null && System.nanoTime() < cachedUntilNanos) {
			return Mono.just(snapshot);
		}
		return worm.probe().thenReturn(Health.up().build())
				.onErrorResume(error -> Mono.just(Health.outOfService().withDetail("worm", "unreachable").build()))
				.doOnNext(health -> {
					this.cached = health;
					this.cachedUntilNanos = System.nanoTime() + CACHE_TTL.toNanos();
				});
	}
}
