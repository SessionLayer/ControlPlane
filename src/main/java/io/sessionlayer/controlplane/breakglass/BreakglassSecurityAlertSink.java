package io.sessionlayer.controlplane.breakglass;

import io.sessionlayer.controlplane.data.runtime.BreakglassActivation;
import java.util.UUID;
import reactor.core.publisher.Mono;

/**
 * The pluggable break-glass alert seam (§7 / FR-ACC-6). A break-glass
 * credential use MUST raise an alert. The
 * {@link AuditLogBreakglassSecurityAlertSink} default audits and logs loudly.
 * Additional transports plug in as sinks. Sinks receive only public ids — never
 * key material or secrets.
 */
public interface BreakglassSecurityAlertSink {

	Mono<Void> authenticated(String identity, UUID nodeId, String sourceIp, String method);

	/**
	 * A break-glass session was opened (activation persisted at Authorize). Default
	 * is a no-op — the alert already fired at {@link #authenticated}, and the
	 * activation carries its own audit; a transport may override to correlate the
	 * session.
	 */
	default Mono<Void> activated(BreakglassActivation activation) {
		return Mono.empty();
	}
}
