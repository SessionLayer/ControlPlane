package io.sessionlayer.controlplane.mtls;

import static org.assertj.core.api.Assertions.assertThat;

import com.google.protobuf.ByteString;
import io.grpc.ManagedChannel;
import io.micrometer.core.instrument.MeterRegistry;
import io.netty.handler.ssl.SslContext;
import io.sessionlayer.controlplane.audit.AuditEventStore;
import io.sessionlayer.controlplane.audit.AuditEventStore.AuditQuery;
import io.sessionlayer.controlplane.breakglass.BreakglassCredentialService;
import io.sessionlayer.controlplane.ca.wire.SshWriter;
import io.sessionlayer.controlplane.data.config.DpRule;
import io.sessionlayer.controlplane.data.config.DpRuleRepository;
import io.sessionlayer.controlplane.data.config.SessionLimitPolicy;
import io.sessionlayer.controlplane.data.config.SessionLimitPolicyRepository;
import io.sessionlayer.controlplane.data.runtime.AuditEvent;
import io.sessionlayer.controlplane.data.runtime.Node;
import io.sessionlayer.controlplane.data.runtime.NodeRepository;
import io.sessionlayer.controlplane.data.runtime.SessionLease;
import io.sessionlayer.controlplane.data.runtime.SessionLeaseRepository;
import io.sessionlayer.controlplane.data.runtime.SshSession;
import io.sessionlayer.controlplane.data.runtime.SshSessionRepository;
import io.sessionlayer.controlplane.grpc.v1.AuthorizationGrpc;
import io.sessionlayer.controlplane.grpc.v1.AuthorizeRequest;
import io.sessionlayer.controlplane.grpc.v1.AuthorizeResponse;
import io.sessionlayer.controlplane.grpc.v1.BreakglassResolution;
import io.sessionlayer.controlplane.grpc.v1.Decision;
import io.sessionlayer.controlplane.grpc.v1.OuterLegAuthGrpc;
import io.sessionlayer.controlplane.grpc.v1.ResolveBreakglassKeyRequest;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import tools.jackson.databind.node.JsonNodeFactory;
import tools.jackson.databind.node.ObjectNode;

class ConcurrentSessionLimitIT extends AbstractMtlsIT {

	private static final JsonNodeFactory JSON = JsonNodeFactory.instance;
	private static final String SOURCE_IP = "203.0.113.9";

	@Autowired
	private NodeRepository nodes;
	@Autowired
	private DpRuleRepository dpRules;
	@Autowired
	private SshSessionRepository sshSessions;
	@Autowired
	private SessionLeaseRepository sessionLeases;
	@Autowired
	private SessionLimitPolicyRepository sessionLimitPolicies;
	@Autowired
	private AuditEventStore auditStore;
	@Autowired
	private BreakglassCredentialService breakglassCredentials;
	@Autowired
	private MeterRegistry meters;

	@Test
	void theNPlusFirstConcurrentSessionIsDeniedWithTheConcurrentLimitNote() {
		String identity = "cap-" + unique();
		UUID nodeId = seedProdNode();
		seedAllow(identity, nodeId, List.of("deploy"), List.of("shell"));
		seedPolicy(identity, 2);
		EnrolledGateway gateway = enroll("gw-cap-" + unique());
		double deniedBefore = limitDeniedCount();

		assertThat(authorize(gateway, identity, nodeId, "deploy").getDecision()).isEqualTo(Decision.DECISION_ALLOW);
		assertThat(authorize(gateway, identity, nodeId, "deploy").getDecision()).isEqualTo(Decision.DECISION_ALLOW);

		AuthorizeResponse third = authorize(gateway, identity, nodeId, "deploy");
		assertThat(third.getDecision()).isEqualTo(Decision.DECISION_DENY);
		assertThat(third.getSessionToken()).isEmpty();
		assertThat(third.hasContext()).isFalse();

		// Exactly two live leases were acquired; the refused one took none (deny wins).
		assertThat(countLive(identity)).isEqualTo(2);

		AuditEvent deny = deniedDecision(identity);
		assertThat(deny.detail().get("note").stringValue()).isEqualTo("concurrent_session_limit");
		assertThat(deny.detail().get("active_sessions").stringValue()).isEqualTo("2");
		assertThat(deny.detail().get("limit").stringValue()).isEqualTo("2");

		assertThat(limitDeniedCount()).isEqualTo(deniedBefore + 1);
	}

	private double limitDeniedCount() {
		var counter = meters.find("sessionlayer.session.limit").tag("outcome", "denied").tag("access_model", "standing")
				.counter();
		return counter == null ? 0 : counter.count();
	}

	// The cap is HARD, not soft. A concurrent BURST of Authorizes for ONE identity
	// at cap L admits EXACTLY L — never more — because the per-identity advisory
	// xact lock serializes count-then-acquire, so a shared/stolen credential can't
	// overshoot the concurrent blast radius. This is the race the sequential tests
	// cannot exercise; without serialization the burst would overshoot.
	@Test
	void aConcurrentBurstForOneIdentityNeverOvershootsTheCap() throws Exception {
		String identity = "burst-" + unique();
		UUID nodeId = seedProdNode();
		seedAllow(identity, nodeId, List.of("deploy"), List.of("shell"));
		int limit = 2;
		seedPolicy(identity, limit);
		EnrolledGateway gateway = enroll("gw-burst-" + unique());

		int burst = 8;
		ExecutorService pool = Executors.newFixedThreadPool(burst);
		try {
			CountDownLatch ready = new CountDownLatch(burst);
			CountDownLatch go = new CountDownLatch(1);
			List<Future<Decision>> futures = new ArrayList<>();
			for (int i = 0; i < burst; i++) {
				futures.add(pool.submit(() -> {
					ready.countDown();
					go.await();
					return authorize(gateway, identity, nodeId, "deploy").getDecision();
				}));
			}
			assertThat(ready.await(15, TimeUnit.SECONDS)).isTrue();
			go.countDown();

			long allows = 0;
			for (Future<Decision> future : futures) {
				if (future.get(30, TimeUnit.SECONDS) == Decision.DECISION_ALLOW) {
					allows++;
				}
			}
			assertThat(allows).isEqualTo(limit); // EXACTLY the cap — the race never overshoots
			assertThat(countLive(identity)).isEqualTo(limit);
		} finally {
			pool.shutdownNow();
		}
	}

	@Test
	void aPerIdentityPolicyOverridesTheClusterDefault() {
		String policied = "policy-" + unique();
		String defaulted = "default-" + unique();
		UUID nodeId = seedProdNode();
		seedAllow(policied, nodeId, List.of("deploy"), List.of("shell"));
		seedAllow(defaulted, nodeId, List.of("deploy"), List.of("shell"));
		seedPolicy(policied, 2);
		EnrolledGateway gateway = enroll("gw-policy-" + unique());

		setClusterDefault(3);
		try {
			authorize(gateway, policied, nodeId, "deploy");
			authorize(gateway, policied, nodeId, "deploy");
			assertThat(authorize(gateway, policied, nodeId, "deploy").getDecision()).isEqualTo(Decision.DECISION_DENY);

			authorize(gateway, defaulted, nodeId, "deploy");
			authorize(gateway, defaulted, nodeId, "deploy");
			assertThat(authorize(gateway, defaulted, nodeId, "deploy").getDecision())
					.isEqualTo(Decision.DECISION_ALLOW);
			assertThat(authorize(gateway, defaulted, nodeId, "deploy").getDecision()).isEqualTo(Decision.DECISION_DENY);
		} finally {
			clearClusterDefault();
		}
	}

	@Test
	void aLeaseFromADifferentGatewayCountsTowardTheCap() {
		String identity = "ha-" + unique();
		UUID nodeId = seedProdNode();
		Node node = nodes.findById(nodeId).block();
		seedAllow(identity, nodeId, List.of("deploy"), List.of("shell"));
		seedPolicy(identity, 2);
		EnrolledGateway peer = enroll("gw-ha-peer-" + unique());
		EnrolledGateway caller = enroll("gw-ha-caller-" + unique());

		// A live session + lease for this identity owned by a DIFFERENT Gateway (as if
		// written by another HA instance to the shared CP DB).
		SshSession peerSession = sshSessions.save(SshSession.create(identity, nodeId, node.name(), "deploy",
				peer.gatewayId(), "gw-ha-peer", "standing", List.of("shell"), null, "peer-rule", null, null, 0L,
				Instant.now().plusSeconds(3600), Instant.now())).block();
		sessionLeases.save(SessionLease.acquire(identity, peerSession.id(), "gw-ha-peer", Instant.now(),
				Instant.now().plusSeconds(3600))).block();

		assertThat(authorize(caller, identity, nodeId, "deploy").getDecision()).isEqualTo(Decision.DECISION_ALLOW);
		assertThat(authorize(caller, identity, nodeId, "deploy").getDecision()).isEqualTo(Decision.DECISION_DENY);
	}

	@Test
	void releasingALeaseFreesASlot() {
		String identity = "free-slot-" + unique();
		UUID nodeId = seedProdNode();
		seedAllow(identity, nodeId, List.of("deploy"), List.of("shell"));
		seedPolicy(identity, 2);
		EnrolledGateway gateway = enroll("gw-free-" + unique());

		authorize(gateway, identity, nodeId, "deploy");
		authorize(gateway, identity, nodeId, "deploy");
		assertThat(authorize(gateway, identity, nodeId, "deploy").getDecision()).isEqualTo(Decision.DECISION_DENY);

		UUID sessionId = sshSessions.findByIdentity(identity).blockFirst().id();
		sessionLeases.releaseBySessionId(sessionId, Instant.now()).block();
		assertThat(countLive(identity)).isEqualTo(1);

		assertThat(authorize(gateway, identity, nodeId, "deploy").getDecision()).isEqualTo(Decision.DECISION_ALLOW);
	}

	@Test
	void anExpiredUnreleasedLeaseNoLongerCountsTowardTheCap() {
		String identity = "leak-" + unique();
		UUID nodeId = seedProdNode();
		Node node = nodes.findById(nodeId).block();
		seedAllow(identity, nodeId, List.of("deploy"), List.of("shell"));
		seedPolicy(identity, 1);
		EnrolledGateway gateway = enroll("gw-leak-" + unique());

		// A leaked lease: unreleased but past its expires_at grant window.
		SshSession stale = sshSessions.save(SshSession.create(identity, nodeId, node.name(), "deploy",
				gateway.gatewayId(), "gw-leak", "standing", List.of("shell"), null, "stale-rule", null, null, 0L,
				Instant.now().minusSeconds(60), Instant.now().minusSeconds(3600))).block();
		sessionLeases.save(SessionLease.acquire(identity, stale.id(), "gw-leak", Instant.now().minusSeconds(3600),
				Instant.now().minusSeconds(60))).block();
		assertThat(countLive(identity)).isEqualTo(0);

		assertThat(authorize(gateway, identity, nodeId, "deploy").getDecision()).isEqualTo(Decision.DECISION_ALLOW);
		assertThat(authorize(gateway, identity, nodeId, "deploy").getDecision()).isEqualTo(Decision.DECISION_DENY);
	}

	// Break-glass is exempt: even with the identity already at its cap, a
	// break-glass
	// Authorize still allows AND consumes no lease (emergency access is neither
	// throttled by the cap nor eats into the normal budget).
	@Test
	void breakGlassIsExemptFromTheCapAndConsumesNoLease() throws Exception {
		String identity = "bg-cap-" + unique();
		UUID nodeId = seedProdNode();
		seedAllow(identity, nodeId, List.of("root"), List.of("shell"));
		seedPolicy(identity, 2);
		byte[] sk = skBlob((byte) 0x55);
		breakglassCredentials.register(sk, identity, List.of("root"), null, null, "admin").block();
		EnrolledGateway gateway = enroll("gw-bgcap-" + unique());

		authorize(gateway, identity, nodeId, "root");
		authorize(gateway, identity, nodeId, "root");
		assertThat(authorize(gateway, identity, nodeId, "root").getDecision()).isEqualTo(Decision.DECISION_DENY);

		BreakglassResolution resolution = resolveKey(gateway, sk, nodeId);
		assertThat(resolution.getBreakglassToken()).isNotBlank();
		assertThat(authorizeBreakglass(gateway, identity, nodeId, resolution.getBreakglassToken()).getDecision())
				.isEqualTo(Decision.DECISION_ALLOW);

		// The break-glass session took no lease — the count is still just the two
		// standing sessions.
		assertThat(countLive(identity)).isEqualTo(2);
	}

	// The Gateway re-Authorizes a live connection with the SAME session_id once
	// decision_ttl elapses. Before the fix, the ssh_session write was a blind
	// INSERT, so the second call's duplicate-key violation rolled back the whole
	// allow tx and surfaced as a policy DENY — breaking every multiplexed channel
	// (second shell, scp/sftp, ControlMaster reuse) past the TTL window. The
	// re-auth must be ALLOWed, its decision must land in the ssh_session row (an
	// UPDATE, not a second row), and its lease must refresh the SAME slot rather
	// than acquiring a second one.
	@Test
	void aReAuthorizeWithTheSameSessionIdIsAllowedAndRefreshesTheSameLease() {
		String identity = "reauth-" + unique();
		UUID nodeId = seedProdNode();
		seedAllow(identity, nodeId, List.of("deploy"), List.of("shell"));
		seedPolicy(identity, 1);
		EnrolledGateway gateway = enroll("gw-reauth-" + unique());
		UUID sessionId = UUID.randomUUID();

		AuthorizeResponse first = authorizeWithSession(gateway, identity, nodeId, "deploy", sessionId);
		assertThat(first.getDecision()).isEqualTo(Decision.DECISION_ALLOW);
		long firstExpiry = first.getContext().getGrantExpiryEpochSeconds();

		AuthorizeResponse second = authorizeWithSession(gateway, identity, nodeId, "deploy", sessionId);
		assertThat(second.getDecision()).isEqualTo(Decision.DECISION_ALLOW);
		assertThat(second.getSessionToken()).isNotEmpty();
		// A genuinely fresh decision, not a cached/duplicate answer to the first call.
		assertThat(second.getContext().getGrantExpiryEpochSeconds()).isGreaterThanOrEqualTo(firstExpiry);

		SshSession session = sshSessions.findById(sessionId).block();
		assertThat(session).isNotNull();
		assertThat(session.grantExpiry().getEpochSecond()).isEqualTo(second.getContext().getGrantExpiryEpochSeconds());

		// Exactly one live lease for this identity/session — the re-auth refreshed the
		// original lease in place rather than acquiring a second one (no double-count).
		assertThat(countLive(identity)).isEqualTo(1);
		SessionLease lease = sessionLeases.findBySessionId(sessionId).block();
		assertThat(lease).isNotNull();
		assertThat(lease.releasedAt()).isNull();
	}

	private AuthorizeResponse authorize(EnrolledGateway gateway, String identity, UUID nodeId, String principal) {
		return authorizeWithSession(gateway, identity, nodeId, principal, UUID.randomUUID());
	}

	private AuthorizeResponse authorizeWithSession(EnrolledGateway gateway, String identity, UUID nodeId,
			String principal, UUID sessionId) {
		AuthorizeRequest request = AuthorizeRequest.newBuilder().setIdentity(identity).setNodeId(nodeId.toString())
				.setRequestedPrincipal(principal).setSourceIp(SOURCE_IP).setSessionId(sessionId.toString()).build();
		return onChannel(gateway, channel -> AuthorizationGrpc.newBlockingStub(channel).authorize(request));
	}

	private AuthorizeResponse authorizeBreakglass(EnrolledGateway gateway, String identity, UUID nodeId, String token) {
		AuthorizeRequest request = AuthorizeRequest.newBuilder().setIdentity(identity).setNodeId(nodeId.toString())
				.setRequestedPrincipal("root").setSourceIp(SOURCE_IP).setSessionId(UUID.randomUUID().toString())
				.setBreakglassToken(token).build();
		return onChannel(gateway, channel -> AuthorizationGrpc.newBlockingStub(channel).authorize(request));
	}

	private BreakglassResolution resolveKey(EnrolledGateway gateway, byte[] sk, UUID nodeId) {
		return onChannel(gateway,
				channel -> OuterLegAuthGrpc.newBlockingStub(channel)
						.resolveBreakglassKey(
								ResolveBreakglassKeyRequest.newBuilder().setSkPublicKeyBlob(ByteString.copyFrom(sk))
										.setSourceIp(SOURCE_IP).setNodeId(nodeId.toString()).build())
						.getResolution());
	}

	private long countLive(String identity) {
		return sessionLeases.countLiveByIdentity(identity, Instant.now()).block();
	}

	private AuditEvent deniedDecision(String identity) {
		return auditStore.search(new AuditQuery(null, identity, "authz.decision", "denied", null, null, null, null,
				null, null, null, Map.of(), null, List.of(), null, 50)).block().items().stream().findFirst()
				.orElseThrow();
	}

	private void setClusterDefault(int limit) {
		db.sql("UPDATE config.operator_settings SET default_max_concurrent_sessions = :n WHERE singleton = true")
				.bind("n", limit).fetch().rowsUpdated().block();
	}

	private void clearClusterDefault() {
		db.sql("UPDATE config.operator_settings SET default_max_concurrent_sessions = NULL WHERE singleton = true")
				.fetch().rowsUpdated().block();
	}

	private <T> T onChannel(EnrolledGateway gateway, java.util.function.Function<ManagedChannel, T> call) {
		SslContext ssl = MtlsTestSupport.clientSslContext(caCertificate(), gateway.certificate(),
				gateway.keyPair().getPrivate());
		ManagedChannel channel = MtlsTestSupport.channel(grpcPort(), ssl);
		try {
			return call.apply(channel);
		} finally {
			shutdown(channel);
		}
	}

	private UUID seedProdNode() {
		ObjectNode labels = JSON.objectNode().put("env", "prod");
		return nodes.save(Node.create("node-" + unique(), null, labels, "agent", "active", "healthy", null, null))
				.map(Node::id).block();
	}

	private void seedAllow(String identity, UUID nodeId, List<String> principals, List<String> capabilities) {
		ObjectNode identitySelector = JSON.objectNode();
		identitySelector.set("identities", JSON.arrayNode().add(identity));
		ObjectNode labelSelector = JSON.objectNode();
		labelSelector.set("env", JSON.objectNode().put("op", "eq").put("value", "prod"));
		dpRules.save(DpRule.create("rule-" + unique(), identitySelector, labelSelector, null, principals, 3600,
				capabilities, "allow", "api")).block();
	}

	private void seedPolicy(String identity, int maxConcurrentSessions) {
		ObjectNode selector = JSON.objectNode();
		selector.set("identities", JSON.arrayNode().add(identity));
		sessionLimitPolicies.save(
				SessionLimitPolicy.create("limit-" + unique(), selector, maxConcurrentSessions, null, null, "api"))
				.block();
	}

	private static byte[] skBlob(byte fill) {
		byte[] q = new byte[65];
		q[0] = 0x04;
		for (int i = 1; i < q.length; i++) {
			q[i] = fill;
		}
		return new SshWriter().writeString("sk-ecdsa-sha2-nistp256@openssh.com").writeString("nistp256").writeString(q)
				.writeString("ssh:").toByteArray();
	}

	private static String unique() {
		return UUID.randomUUID().toString().substring(0, 8);
	}
}
