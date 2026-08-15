package io.sessionlayer.controlplane.breakglass;

import java.util.List;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

/**
 * Fans a break-glass alert out to every registered
 * {@link BreakglassSecurityAlertSink}. A failing sink is logged loudly — a
 * dropped security alert must never be silent.
 */
@Component
public class BreakglassSecurityAlerts {

	private static final Logger LOG = LoggerFactory.getLogger(BreakglassSecurityAlerts.class);

	private final List<BreakglassSecurityAlertSink> sinks;

	public BreakglassSecurityAlerts(List<BreakglassSecurityAlertSink> sinks) {
		this.sinks = sinks;
	}

	public Mono<Void> authenticated(String identity, UUID nodeId, String sourceIp, String method) {
		return Flux.fromIterable(sinks)
				.flatMap(sink -> sink.authenticated(identity, nodeId, sourceIp, method).onErrorResume(failed -> {
					LOG.error(
							"SECURITY: break-glass alert sink {} FAILED for identity {} ({}) — authentication stands "
									+ "but this alert was not delivered; investigate immediately",
							sink.getClass().getSimpleName(), identity, method, failed);
					return Mono.empty();
				})).then();
	}
}
