package io.sessionlayer.controlplane.audit;

import io.sessionlayer.controlplane.data.runtime.AuditEvent;
import reactor.core.publisher.Mono;

/**
 * Pluggable audit exporter seam. Ships events off-box after append (separate
 * from {@link AuditEventStore}); best-effort, never rolls back or fails the
 * audited action.
 */
public interface AuditForwarder {

	Mono<Void> forward(AuditEvent event);
}
