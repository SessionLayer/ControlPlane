package io.sessionlayer.controlplane.breakglass;

import io.sessionlayer.controlplane.audit.AuditEventStore;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

/**
 * The default {@link BreakglassSecurityAlertSink}: audits and logs break-glass
 * authentication to the one correlated audit stream. The
 * action {@code breakglass.authenticated} is what auditors query. Carries
 * public ids only — no key material, no resolving secret.
 */
@Component
public class AuditLogBreakglassSecurityAlertSink implements BreakglassSecurityAlertSink {

	private static final Logger LOG = LoggerFactory.getLogger(AuditLogBreakglassSecurityAlertSink.class);

	private final AuditEventStore audit;

	public AuditLogBreakglassSecurityAlertSink(AuditEventStore audit) {
		this.audit = audit;
	}

	@Override
	public Mono<Void> authenticated(String identity, UUID nodeId, String sourceIp, String method) {
		LOG.error(
				"SECURITY: break-glass credential authenticated — identity={} node={} source_ip={} method={}; a "
						+ "mandatory-review activation follows if a session is opened",
				identity, nodeId, sourceIp, method);
		Map<String, String> detail = new HashMap<>();
		detail.put("method", method);
		if (sourceIp != null) {
			detail.put("source_ip", sourceIp);
		}
		return audit.record("system:break-glass", identity, "breakglass.authenticated", "success", null, nodeId,
				detail);
	}
}
