package io.sessionlayer.controlplane.jit;

import java.time.Duration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

@Component
@ConditionalOnProperty(value = "sessionlayer.jit.expiry.enabled", havingValue = "true", matchIfMissing = true)
public class JitExpiryScheduler {

	private static final Logger LOG = LoggerFactory.getLogger(JitExpiryScheduler.class);

	private final JitLifecycleService lifecycle;

	public JitExpiryScheduler(JitLifecycleService lifecycle) {
		this.lifecycle = lifecycle;
	}

	@Scheduled(fixedDelayString = "${sessionlayer.jit.expiry.interval:PT5M}", initialDelayString = "${sessionlayer.jit.expiry.interval:PT5M}")
	public void sweep() {
		try {
			lifecycle.expireOverdue().doOnNext(expired -> {
				if (expired > 0) {
					LOG.info("jit expiry sweep transitioned {} overdue request(s) to EXPIRED", expired);
				}
			}).onErrorResume(error -> {
				LOG.warn("jit expiry sweep failed (lazy read-time expiry still protects the grant path): {}",
						error.toString());
				return Mono.empty();
			}).block(Duration.ofSeconds(30));
		} catch (RuntimeException blockTimeout) {
			LOG.warn("jit expiry sweep timed out (lazy read-time expiry still protects the grant path): {}",
					blockTimeout.toString());
		}
	}
}
