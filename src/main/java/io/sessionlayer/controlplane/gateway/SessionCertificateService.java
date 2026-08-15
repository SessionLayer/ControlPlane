package io.sessionlayer.controlplane.gateway;

import io.sessionlayer.controlplane.audit.AuditEventStore;
import io.sessionlayer.controlplane.ca.CaSignerService;
import io.sessionlayer.controlplane.ca.CertificateRequest;
import io.sessionlayer.controlplane.ca.OpenSshCertificate;
import io.sessionlayer.controlplane.ca.SshCertSigner;
import io.sessionlayer.controlplane.ca.backend.CaSigningFailedException;
import io.sessionlayer.controlplane.ca.cert.CertificateParameters;
import io.sessionlayer.controlplane.ca.cert.CertificateProfiles;
import io.sessionlayer.controlplane.ca.key.SshEcdsaPublicKeys;
import io.sessionlayer.controlplane.data.runtime.GatewayIdentity;
import io.sessionlayer.controlplane.data.runtime.GatewayIdentityRepository;
import io.sessionlayer.controlplane.data.runtime.SessionSigningToken;
import java.security.interfaces.ECPublicKey;
import java.time.Instant;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

@Service
public class SessionCertificateService {

	private final SessionSigningTokenService tokenService;
	private final CaSignerService caSigner;
	private final GatewayIdentityRepository gatewayIdentities;
	private final AuditEventStore audit;

	public SessionCertificateService(SessionSigningTokenService tokenService, CaSignerService caSigner,
			GatewayIdentityRepository gatewayIdentities, AuditEventStore audit) {
		this.tokenService = tokenService;
		this.caSigner = caSigner;
		this.gatewayIdentities = gatewayIdentities;
		this.audit = audit;
	}

	/**
	 * Sign the inner-leg cert authorised by {@code rawToken} for the caller
	 * {@code callerGatewayId}. Fails closed (generic) on an inactive caller, a
	 * cross-gateway / cross-session / expired / replayed token, or a context that
	 * disagrees with the token. A malformed subject key is an
	 * {@code INVALID_ARGUMENT}.
	 */
	public Mono<SignedInnerCert> sign(UUID callerGatewayId, String presentedFingerprint, String rawToken,
			byte[] subjectPublicKeyBlob, SignRequestContext context) {
		ECPublicKey subjectKey;
		try {
			subjectKey = SshEcdsaPublicKeys.parse(subjectPublicKeyBlob);
		} catch (RuntimeException malformed) {
			// Audited here rather than by the onErrorResume chain below, which this
			// early return never enters: a refusal that leaves no trace is the one
			// failure mode the signing path must not have, whatever the reason.
			GatewayRequestException invalid = new GatewayRequestException(
					GatewayRequestException.Reason.INVALID_ARGUMENT, "invalid subject public key");
			return audit.record(callerGatewayId == null ? "unknown" : callerGatewayId.toString(), null, "session.sign",
					"denied", null, null, Map.of("reason", invalid.reason().name())).then(Mono.error(invalid));
		}
		return requireAuthorizedGateway(callerGatewayId, presentedFingerprint)
				.then(tokenService.consume(rawToken, callerGatewayId, context))
				.flatMap(token -> caSigner.activeSigner("session")
						// OpenSSH cert assembly + ECDSA sign is CPU-bound — off the event loop.
						.flatMap(signer -> Mono.fromCallable(() -> mint(signer, subjectKey, token))
								.subscribeOn(Schedulers.boundedElastic()))
						.flatMap(signed -> audit
								.record(callerGatewayId.toString(), token.principal(), "session.sign", "success",
										token.sessionId(), token.nodeId(), Map.of("key_id", signed.keyId()))
								.thenReturn(signed)))
				// Every fail-closed denial on the signing path is audited
				// (generic to the client; the category reason + caller id stay server-side).
				.onErrorResume(GatewayRequestException.class,
						denial -> audit
								.record(callerGatewayId == null ? "unknown" : callerGatewayId.toString(), null,
										"session.sign", "denied", null, null, Map.of("reason", denial.reason().name()))
								.then(Mono.error(denial)))
				// A fail-closed signer-unavailable is not a GatewayRequestException;
				// audit it distinctly so a CA-availability incident is forensically visible.
				.onErrorResume(CaSignerService.NoSignerAvailable.class,
						unavailable -> audit
								.record(callerGatewayId == null ? "unknown" : callerGatewayId.toString(), null,
										"session.sign", "denied", null, null, Map.of("reason", "ca_unavailable"))
								.then(Mono.error(unavailable)))
				// A backend that was reached and then refused (a key service returning a
				// signature that fails verification against the pinned key) is neither a
				// client fault nor an absent CA, and without its own branch it escaped both
				// and was never audited at all. The reason is a fixed constant: a key
				// service's response text must not reach the audit trail.
				.onErrorResume(CaSigningFailedException.class,
						failed -> audit
								.record(callerGatewayId == null ? "unknown" : callerGatewayId.toString(), null,
										"session.sign", "denied", null, null, Map.of("reason", "ca_signing_failed"))
								.then(Mono.error(failed)));
	}

	// The caller's identity must be active AND the presented client cert must pin
	// to the identity's current or previous fingerprint (a superseded/stolen cert
	// is refused).
	private Mono<GatewayIdentity> requireAuthorizedGateway(UUID callerGatewayId, String presentedFingerprint) {
		if (callerGatewayId == null || presentedFingerprint == null) {
			return Mono.error(denied());
		}
		return gatewayIdentities.findById(callerGatewayId).switchIfEmpty(Mono.error(denied())).flatMap(identity -> {
			boolean active = "active".equals(identity.status());
			boolean pinned = presentedFingerprint.equals(identity.fingerprint())
					|| presentedFingerprint.equals(identity.prevFingerprint());
			return active && pinned ? Mono.just(identity) : Mono.error(denied());
		});
	}

	// Compute the cert parameters ONCE, sign over the presented public key, and
	// derive the response validity from the same parameters (no re-clocking).
	private static SignedInnerCert mint(SshCertSigner signer, ECPublicKey subjectKey, SessionSigningToken token) {
		// Minimal CP-internal path: the human "identity" component of the key id is the
		// principal (the real human identity distinct from the Linux login is supplied
		// elsewhere). key_id = session_id + identity.
		String principal = token.principal();
		Set<String> capabilities = new HashSet<>(token.capabilities());
		// The node-facing inner cert carries NO source-address. The node validates a
		// cert's source-address against the GATEWAY's peer IP (the inner leg's TCP
		// source), not the SSH client's, so pinning the client IP here rejects the
		// valid cert in any multi-host / NAT / bridged deployment. Source-IP
		// enforcement lives on the OUTER leg + the Authorize decision, which see the
		// real client IP.
		CertificateParameters params = CertificateProfiles.innerLegSessionCert(token.sessionId().toString(), principal,
				principal, null, capabilities, serial(token.id()), Instant.now());
		OpenSshCertificate cert = signer.signCertificate(new CertificateRequest(subjectKey, params));
		return new SignedInnerCert(cert.certificateLine(), cert.blob(), cert.keyId(),
				params.validAfter().getEpochSecond(), params.validBefore().getEpochSecond());
	}

	private static long serial(UUID id) {
		return id.getMostSignificantBits() & Long.MAX_VALUE;
	}

	private static GatewayRequestException denied() {
		return new GatewayRequestException(GatewayRequestException.Reason.PERMISSION_DENIED,
				"session signing request refused");
	}
}
