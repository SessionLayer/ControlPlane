package io.sessionlayer.controlplane.audit;

import io.sessionlayer.controlplane.data.runtime.AuditEvent;
import reactor.core.publisher.Mono;

public interface AuditForwarder {

	Mono<Void> forward(AuditEvent event);
}
