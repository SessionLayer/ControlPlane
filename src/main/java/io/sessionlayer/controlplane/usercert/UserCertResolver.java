package io.sessionlayer.controlplane.usercert;

import io.sessionlayer.controlplane.audit.AuditEventStore;
import io.sessionlayer.controlplane.ca.CaRotationService;
import io.sessionlayer.controlplane.ca.cert.UserCertificateVerifier;
import io.sessionlayer.controlplane.ca.cert.UserCertificateVerifier.Verdict;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

/**
 * Resolves an outer-leg OpenSSH user certificate to its CP identity.
 */
@Service
public class UserCertResolver {

	private static final Duration CLOCK_SKEW = Duration.ofSeconds(60);

	private final CaRotationService caRotation;
	private final AuditEventStore audit;

	public UserCertResolver(CaRotationService caRotation, AuditEventStore audit) {
		this.caRotation = caRotation;
		this.audit = audit;
	}

	public record Resolved(String identity, List<String> principals) {
	}

	public Mono<Resolved> resolve(byte[] certificateBlob, String sourceIp) {
		if (certificateBlob == null || certificateBlob.length == 0) {
			return audit("system", "denied", "empty_certificate", sourceIp).then(Mono.empty());
		}
		return caRotation.trustedCaKeys("user").flatMap(trusted -> {
			Verdict verdict = UserCertificateVerifier.verify(certificateBlob, trusted, sourceIp, Instant.now(),
					CLOCK_SKEW);
			if (!verdict.resolved()) {
				return audit("system", "denied", verdict.reason(), sourceIp).then(Mono.empty());
			}
			return audit(verdict.identity(), "success", "ok", sourceIp)
					.thenReturn(new Resolved(verdict.identity(), verdict.principals()));
		}).onErrorResume(err -> audit("system", "error", "evaluation_error", sourceIp).then(Mono.empty()));
	}

	private Mono<Void> audit(String actor, String outcome, String reason, String sourceIp) {
		return audit.record(actor, null, "usercert.resolve", outcome, null, null,
				Map.of("reason", reason, "source_ip", sourceIp == null ? "" : sourceIp));
	}
}
