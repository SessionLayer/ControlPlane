package io.sessionlayer.controlplane.audit;

import io.sessionlayer.controlplane.data.runtime.AuditEvent;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import reactor.core.publisher.Mono;

public final class CapturingAuditForwarder implements AuditForwarder {

	private final List<AuditEvent> captured = new CopyOnWriteArrayList<>();

	@Override
	public Mono<Void> forward(AuditEvent event) {
		return Mono.fromRunnable(() -> captured.add(event));
	}

	public List<AuditEvent> captured() {
		return List.copyOf(captured);
	}
}
