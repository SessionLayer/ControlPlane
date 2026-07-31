package io.sessionlayer.controlplane.mtls;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.catchThrowableOfType;

import io.grpc.Status;
import io.grpc.StatusRuntimeException;
import io.sessionlayer.controlplane.authz.SessionLifecycleService;
import io.sessionlayer.controlplane.data.runtime.SessionLease;
import io.sessionlayer.controlplane.data.runtime.SessionLeaseRepository;
import io.sessionlayer.controlplane.data.runtime.SshSession;
import io.sessionlayer.controlplane.data.runtime.SshSessionRepository;
import io.sessionlayer.controlplane.gateway.GatewayDirectoryService;
import io.sessionlayer.controlplane.gateway.GatewayEnrollmentTokenService.MintedEnrollmentToken;
import io.sessionlayer.controlplane.gateway.GatewayRequestException;
import io.sessionlayer.controlplane.web.ApiProblemException;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

/**
 * Removal frees a Gateway name, so the question the previous session's
 * impersonation defect makes unavoidable is what a free-then-re-enroll buys.
 * Two properties must hold: freeing a name cannot route around the
 * reserved-name rule, and a re-enrollment under a freed name inherits nothing
 * from the identity that was removed.
 */
class GatewayRemovalReenrollmentIT extends AbstractMtlsIT {

	@Autowired
	private GatewayDirectoryService directory;
	@Autowired
	private SshSessionRepository sshSessions;
	@Autowired
	private SessionLeaseRepository leases;
	@Autowired
	private SessionLifecycleService lifecycle;

	/**
	 * The reserved-name rule is evaluated from the Control Plane's configured
	 * hostnames, not from what the identity table happens to contain, at BOTH mint
	 * and enroll. Removing rows therefore cannot widen what may be enrolled — but
	 * that is an argument, so exercise it: free a name, then try the reserved one.
	 */
	@Test
	void freeingANameDoesNotMakeTheControlPlanesOwnHostnameEnrollable() {
		String name = "gw-free-" + suffix();
		EnrolledGateway enrolled = enroll(name);
		directory.remove(enrolled.gatewayId(), false, "operator").block();
		assertThat(gatewayIdentities.findByName(name).blockOptional()).isEmpty();

		String cpHostname = "controlplane";
		MintedEnrollmentToken minted = enrollmentTokens.mint(cpHostname, "operator", Duration.ofMinutes(10)).block();
		StatusRuntimeException refused = catchThrowableOfType(StatusRuntimeException.class,
				() -> enrollWithToken(cpHostname, minted.rawToken()));
		assertThat(refused.getStatus().getCode()).isEqualTo(Status.Code.INVALID_ARGUMENT);
		assertThat(gatewayIdentities.findByName(cpHostname).blockOptional()).isEmpty();
	}

	/**
	 * The removed identity's session is orphaned, never inherited: the FK nulls
	 * {@code gateway_id}, and the lifecycle RPCs compare the caller's identity id,
	 * which a re-enrollment never reuses. Both the new Gateway and the removed one
	 * are refused, so the session can be torn down by neither — fail-closed, and
	 * with no path for the new holder of the name to end or extend it.
	 *
	 * <p>
	 * Deliberately over a LIVE session and therefore a forced removal: inheriting a
	 * session that is still running is the case where a hijack would matter, and
	 * arranging an already-ended one to keep the removal unforced would test the
	 * weaker scenario.
	 */
	@Test
	void aReEnrolledNameCannotAddressTheRemovedIdentitysSession() {
		String name = "gw-reuse-" + suffix();
		EnrolledGateway original = enroll(name);
		String identity = "alice-" + suffix();

		SshSession session = sshSessions.save(SshSession.create(identity, null, null, "root", original.gatewayId(),
				name, "standing", List.of("shell"), null, null, null, null, 0L, Instant.now().plus(Duration.ofHours(1)),
				Instant.now())).block();
		SessionLease lease = leases.save(SessionLease.acquire(identity, session.id(), name, Instant.now(),
				Instant.now().plus(Duration.ofHours(1)))).block();
		assertThat(leases.countLiveByIdentity(identity, Instant.now()).block()).isEqualTo(1L);

		// The open session now blocks an unforced removal, which is the guard doing
		// its job — assert it here so this test says why it has to force rather than
		// leaving a bare `true` to be read as carelessness.
		ApiProblemException refused = catchThrowableOfType(ApiProblemException.class,
				() -> directory.remove(original.gatewayId(), false, "operator").block());
		assertThat(refused.getMessage()).contains("1 open session(s)");

		directory.remove(original.gatewayId(), true, "operator").block();

		// The session outlives the identity with no owner: history is preserved and
		// the row cannot be claimed by whoever takes the name next.
		assertThat(sshSessions.findById(session.id()).block().gatewayId()).isNull();
		// And the slot stays occupied. A removal that silently released leases would
		// let the identity exceed its cap while its real sessions are still running;
		// over-counting until the reaper is the fail-safe direction.
		assertThat(leases.countLiveByIdentity(identity, Instant.now()).block()).isEqualTo(1L);
		assertThat(leases.findById(lease.id()).block().releasedAt()).isNull();

		EnrolledGateway reEnrolled = enroll(name);
		assertThat(reEnrolled.gatewayId()).isNotEqualTo(original.gatewayId());

		GatewayRequestException byNewHolder = catchThrowableOfType(GatewayRequestException.class, () -> lifecycle
				.endSession(reEnrolled.gatewayId(), session.id(), "claiming a session I never had").block());
		assertThat(byNewHolder.reason()).isEqualTo(GatewayRequestException.Reason.PERMISSION_DENIED);

		GatewayRequestException byRemoved = catchThrowableOfType(GatewayRequestException.class,
				() -> lifecycle.endSession(original.gatewayId(), session.id(), "the removed identity").block());
		assertThat(byRemoved.reason()).isEqualTo(GatewayRequestException.Reason.PERMISSION_DENIED);

		// The forced removal stamped the end itself, so the session is closed and
		// ownerless — and the lease it held still counts, which is the property this
		// test pins that the forced-removal tests do not.
		SshSession orphaned = sshSessions.findById(session.id()).block();
		assertThat(orphaned.endedAt()).isNotNull();
		assertThat(orphaned.endReason()).isEqualTo("gateway_removed");
		assertThat(leases.countLiveByIdentity(identity, Instant.now()).block()).isEqualTo(1L);
	}

	/**
	 * The removed identity is refused everywhere the Control Plane resolves a
	 * caller, so removal takes the Gateway down immediately rather than leaving it
	 * half-live.
	 */
	@Test
	void aRemovedIdentityIsGoneFromEveryCallerLookup() {
		String name = "gw-gone-" + suffix();
		EnrolledGateway enrolled = enroll(name);
		assertThat(gatewayIdentities.findById(enrolled.gatewayId()).blockOptional()).isPresent();

		directory.remove(enrolled.gatewayId(), false, "operator").block();

		assertThat(gatewayIdentities.findById(enrolled.gatewayId()).blockOptional()).isEmpty();
		// The certificate is still valid and still chains to the internal CA, so the
		// refusal has to come from the identity lookup — which is exactly what makes
		// removal effective without a revocation list.
		StatusRuntimeException heartbeat = catchThrowableOfType(StatusRuntimeException.class,
				() -> presenceHeartbeat(enrolled, "any-node", "10.0.0.9:9443"));
		assertThat(heartbeat.getStatus().getCode()).isEqualTo(Status.Code.UNAUTHENTICATED);
	}

	private static String suffix() {
		return UUID.randomUUID().toString().substring(0, 8);
	}
}
