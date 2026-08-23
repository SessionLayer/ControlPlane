package io.sessionlayer.controlplane.breakglass;

import io.sessionlayer.controlplane.data.runtime.BreakglassActivation;
import java.util.UUID;
import reactor.core.publisher.Mono;

public interface BreakglassSecurityAlertSink {

	Mono<Void> authenticated(String identity, UUID nodeId, String sourceIp, String method);

	default Mono<Void> activated(BreakglassActivation activation) {
		return Mono.empty();
	}
}
