package io.sessionlayer.controlplane.mtls;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.catchThrowableOfType;

import io.grpc.ManagedChannel;
import io.grpc.Status;
import io.grpc.StatusRuntimeException;
import io.netty.handler.ssl.SslContext;
import io.sessionlayer.controlplane.ca.mtls.LeafCertificateSpec;
import io.sessionlayer.controlplane.ca.mtls.LeafPurpose;
import io.sessionlayer.controlplane.data.runtime.Node;
import io.sessionlayer.controlplane.data.runtime.NodeHostKey;
import io.sessionlayer.controlplane.data.runtime.NodeHostKeyRepository;
import io.sessionlayer.controlplane.data.runtime.NodeRepository;
import io.sessionlayer.controlplane.data.runtime.Presence;
import io.sessionlayer.controlplane.data.runtime.PresenceRepository;
import io.sessionlayer.controlplane.grpc.v1.PresenceGrpc;
import io.sessionlayer.controlplane.grpc.v1.PresenceHeartbeatRequest;
import io.sessionlayer.controlplane.grpc.v1.PresenceHeartbeatResponse;
import io.sessionlayer.controlplane.grpc.v1.PresenceReleaseResponse;
import io.sessionlayer.controlplane.node.NodeView;
import io.sessionlayer.controlplane.node.NodeViewService;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.DataIntegrityViolationException;
import tools.jackson.databind.node.JsonNodeFactory;
import tools.jackson.databind.node.ObjectNode;

class PresenceServiceIT extends AbstractMtlsIT {

	private static final JsonNodeFactory JSON = JsonNodeFactory.instance;
	private static final String ADDR_A = "10.9.0.1:7000";
	private static final String ADDR_B = "10.9.0.2:7000";

	@Autowired
	private NodeRepository nodes;
	@Autowired
	private NodeHostKeyRepository hostKeys;
	@Autowired
	private PresenceRepository presences;
	@Autowired
	private NodeViewService nodeViews;

	@Test
	void heartbeatByNameClaimsAndWritesARowKeyedByTheNodeUuid() {
		String nameA = "gw-pres-a-" + unique();
		EnrolledGateway gwA = enroll(nameA);
		Node node = seedAgentNode();

		PresenceHeartbeatResponse claim = presenceHeartbeat(gwA, node.name(), ADDR_A);

		// The owner is derived from the AUTHENTICATED peer (its gateway_identity.name),
		// never anything in the request (which carries no owner at all).
		assertThat(claim.getOwningGatewayId()).isEqualTo(nameA);
		assertThat(claim.getIsSelfOwner()).isTrue();
		assertThat(claim.getGatewayAddr()).isEqualTo(ADDR_A);
		assertThat(claim.getNonce()).isEqualTo(1L);
		assertThat(claim.getNonceId()).isNotBlank();
		assertThat(claim.getLastSeenEpochMs()).isPositive();

		// The heartbeat-by-NAME resolved to the node's UUID and wrote the presence row
		// there (the FK is intact) — this is the regression guard for the name-vs-UUID
		// routing bug: a UUID-only parse would have written nothing.
		Presence row = presences.findById(node.id()).block();
		assertThat(row).isNotNull();
		assertThat(row.owningGateway()).isEqualTo(nameA);
		assertThat(row.nonceId().toString()).isEqualTo(claim.getNonceId());
	}

	@Test
	void ownerRefreshKeepsTheSameNonceAndNonceId() {
		String nameA = "gw-pres-ref-" + unique();
		EnrolledGateway gwA = enroll(nameA);
		Node node = seedAgentNode();

		PresenceHeartbeatResponse claim = presenceHeartbeat(gwA, node.name(), ADDR_A);
		PresenceHeartbeatResponse refresh = presenceHeartbeat(gwA, node.name(), ADDR_A);

		assertThat(refresh.getIsSelfOwner()).isTrue();
		assertThat(refresh.getOwningGatewayId()).isEqualTo(nameA);
		assertThat(refresh.getNonce()).isEqualTo(claim.getNonce());
		assertThat(refresh.getNonceId()).isEqualTo(claim.getNonceId());
		assertThat(refresh.getLastSeenEpochMs()).isGreaterThanOrEqualTo(claim.getLastSeenEpochMs());
	}

	@Test
	void aDifferentGatewayAgainstAFreshOwnerIsStandbyAndDoesNotTakeOver() {
		String nameA = "gw-pres-own-" + unique();
		EnrolledGateway gwA = enroll(nameA);
		EnrolledGateway gwB = enroll("gw-pres-sby-" + unique());
		Node node = seedAgentNode();

		PresenceHeartbeatResponse claim = presenceHeartbeat(gwA, node.name(), ADDR_A);
		PresenceHeartbeatResponse standby = presenceHeartbeat(gwB, node.name(), ADDR_B);

		assertThat(standby.getIsSelfOwner()).isFalse();
		assertThat(standby.getOwningGatewayId()).isEqualTo(nameA);
		assertThat(standby.getGatewayAddr()).isEqualTo(ADDR_A);
		assertThat(standby.getNonce()).isEqualTo(claim.getNonce());
		assertThat(standby.getNonceId()).isEqualTo(claim.getNonceId());
	}

	@Test
	void aStandbyTakesOverAStaleOwnerWithNoncePlusOne() {
		EnrolledGateway gwA = enroll("gw-pres-stale-a-" + unique());
		String nameB = "gw-pres-stale-b-" + unique();
		EnrolledGateway gwB = enroll(nameB);
		Node node = seedAgentNode();

		PresenceHeartbeatResponse claim = presenceHeartbeat(gwA, node.name(), ADDR_A);
		ageOwnerStale(node.id());
		PresenceHeartbeatResponse takeover = presenceHeartbeat(gwB, node.name(), ADDR_B);

		assertThat(takeover.getIsSelfOwner()).isTrue();
		assertThat(takeover.getOwningGatewayId()).isEqualTo(nameB);
		assertThat(takeover.getGatewayAddr()).isEqualTo(ADDR_B);
		assertThat(takeover.getNonce()).isEqualTo(claim.getNonce() + 1);
		assertThat(takeover.getNonceId()).isNotEqualTo(claim.getNonceId());
	}

	@Test
	void aSupersededOwnerReturningIsFencedToStandby() {
		String nameA = "gw-pres-fence-a-" + unique();
		EnrolledGateway gwA = enroll(nameA);
		String nameB = "gw-pres-fence-b-" + unique();
		EnrolledGateway gwB = enroll(nameB);
		Node node = seedAgentNode();

		presenceHeartbeat(gwA, node.name(), ADDR_A);
		ageOwnerStale(node.id());
		PresenceHeartbeatResponse takeover = presenceHeartbeat(gwB, node.name(), ADDR_B);

		PresenceHeartbeatResponse fenced = presenceHeartbeat(gwA, node.name(), ADDR_A);
		assertThat(fenced.getIsSelfOwner()).isFalse();
		assertThat(fenced.getOwningGatewayId()).isEqualTo(nameB);
		assertThat(fenced.getNonce()).isEqualTo(takeover.getNonce());
	}

	@Test
	void theMonotonicTriggerRejectsALowerNonceWrite() {
		EnrolledGateway gwA = enroll("gw-pres-mono-" + unique());
		Node node = seedAgentNode();
		presenceHeartbeat(gwA, node.name(), ADDR_A); // nonce = 1

		// The fencing token the service relies on: any write that LOWERS the nonce is
		// refused at the DB (a stale/duplicated re-claim can never rewind ownership).
		// Assert the specific exception the trigger's ERRCODE=check_violation maps to
		// (matching every other DB-constraint IT), not bare Exception: a typo'd column
		// or an unrelated connection blip must NOT satisfy this, since this is the
		// only test for the fencing invariant itself.
		assertThatThrownBy(() -> db.sql("UPDATE runtime.presence SET nonce = 0 WHERE node_id = :id")
				.bind("id", node.id()).fetch().rowsUpdated().block())
				.isInstanceOf(DataIntegrityViolationException.class);
	}

	@Test
	void anUnknownNodeNameFailsClosed() {
		EnrolledGateway gwA = enroll("gw-pres-unknown-" + unique());

		StatusRuntimeException refused = catchThrowableOfType(StatusRuntimeException.class,
				() -> presenceHeartbeat(gwA, "no-such-node-" + unique(), ADDR_A));
		assertThat(refused.getStatus().getCode()).isEqualTo(Status.Code.PERMISSION_DENIED);
	}

	@Test
	void anAgentAuthenticatedPeerCannotClaimOwnership() {
		Node node = seedAgentNode();
		KeyPair agentKey = MtlsTestSupport.generateEcKeyPair();
		X509Certificate agentCert = agentClientCert(agentKey.getPublic(), UUID.randomUUID());

		StatusRuntimeException refused = catchThrowableOfType(StatusRuntimeException.class,
				() -> heartbeatWithCert(agentCert, agentKey.getPrivate(), node.name(), ADDR_A));
		assertThat(refused.getStatus().getCode()).isEqualTo(Status.Code.PERMISSION_DENIED);
		assertThat(presences.findById(node.id()).block()).isNull();
	}

	@Test
	void aLockedGatewayCannotClaimOwnership() {
		EnrolledGateway gwA = enroll("gw-pres-locked-" + unique());
		Node node = seedAgentNode();
		lockGateway(gwA);

		StatusRuntimeException refused = catchThrowableOfType(StatusRuntimeException.class,
				() -> presenceHeartbeat(gwA, node.name(), ADDR_A));
		assertThat(refused.getStatus().getCode()).isEqualTo(Status.Code.PERMISSION_DENIED);
		assertThat(presences.findById(node.id()).block()).isNull();
	}

	@Test
	void releaseLetsAStandbyClaimImmediately() {
		EnrolledGateway gwA = enroll("gw-pres-rel-a-" + unique());
		String nameB = "gw-pres-rel-b-" + unique();
		EnrolledGateway gwB = enroll(nameB);
		Node node = seedAgentNode();

		PresenceHeartbeatResponse claim = presenceHeartbeat(gwA, node.name(), ADDR_A);
		PresenceReleaseResponse release = presenceRelease(gwA, node.name());
		assertThat(release.getReleased()).isTrue();

		PresenceHeartbeatResponse takeover = presenceHeartbeat(gwB, node.name(), ADDR_B);
		assertThat(takeover.getIsSelfOwner()).isTrue();
		assertThat(takeover.getOwningGatewayId()).isEqualTo(nameB);
		assertThat(takeover.getNonce()).isEqualTo(claim.getNonce() + 1);
	}

	@Test
	void releaseByANonOwnerIsANoOp() {
		String nameA = "gw-pres-noop-a-" + unique();
		EnrolledGateway gwA = enroll(nameA);
		EnrolledGateway gwB = enroll("gw-pres-noop-b-" + unique());
		Node node = seedAgentNode();

		presenceHeartbeat(gwA, node.name(), ADDR_A);
		PresenceReleaseResponse release = presenceRelease(gwB, node.name());
		assertThat(release.getReleased()).isFalse();

		PresenceHeartbeatResponse refresh = presenceHeartbeat(gwA, node.name(), ADDR_A);
		assertThat(refresh.getIsSelfOwner()).isTrue();
		assertThat(refresh.getOwningGatewayId()).isEqualTo(nameA);
		assertThat(refresh.getNonce()).isEqualTo(1L);
	}

	@Test
	void presenceIsDurableInPostgresAcrossACpRestart() {
		String nameA = "gw-pres-durable-" + unique();
		EnrolledGateway gwA = enroll(nameA);
		Node node = seedAgentNode();

		PresenceHeartbeatResponse claim = presenceHeartbeat(gwA, node.name(), ADDR_A);

		// Presence lives in Postgres, not in-process memory: a freshly (re)started CP
		// reads the exact same authoritative row. Read it back straight from the store.
		Presence persisted = presences.findById(node.id()).block();
		assertThat(persisted).isNotNull();
		assertThat(persisted.owningGateway()).isEqualTo(nameA);
		assertThat(persisted.gatewayAddr()).isEqualTo(ADDR_A);
		assertThat(persisted.nonce()).isEqualTo(claim.getNonce());
		assertThat(persisted.nonceId().toString()).isEqualTo(claim.getNonceId());
	}

	@Test
	void aRealHeartbeatIsWhatTheNodeApiReportsAsHealthAndOwner() {
		String nameA = "gw-pres-view-" + unique();
		EnrolledGateway gwA = enroll(nameA);
		Node node = seedAnchoredAgentNode();

		assertThat(view(node).health()).isEqualTo("unknown");

		presenceHeartbeat(gwA, node.name(), ADDR_A);

		NodeView claimed = view(node);
		assertThat(claimed.health()).isEqualTo("healthy");
		// The owner is the gateway NAME (the HA routing key the rest of the plane
		// speaks), never its uuid.
		assertThat(claimed.owningGateway()).isEqualTo(nameA);

		ageOwnerStale(node.id());

		NodeView stale = view(node);
		assertThat(stale.health()).isEqualTo("unreachable");
		assertThat(stale.owningGateway()).isNull();
	}

	private NodeView view(Node node) {
		return nodeViews.of(nodes.findById(node.id()).block()).block();
	}

	private void ageOwnerStale(UUID nodeId) {
		Long updated = db.sql("UPDATE runtime.presence SET last_seen = now() - interval '1 hour' WHERE node_id = :id")
				.bind("id", nodeId).fetch().rowsUpdated().block();
		assertThat(updated).isEqualTo(1L);
	}

	private void lockGateway(EnrolledGateway gateway) {
		Long updated = db.sql("UPDATE runtime.gateway_identity SET status = 'locked' WHERE id = :id")
				.bind("id", gateway.gatewayId()).fetch().rowsUpdated().block();
		assertThat(updated).isEqualTo(1L);
	}

	private X509Certificate agentClientCert(PublicKey publicKey, UUID agentId) {
		return mtlsCa.activeBackend().block()
				.issueLeaf(new LeafCertificateSpec(publicKey, "probe-agent", List.of("probe-agent"),
						List.of(AgentIdentityUri.of(agentId)), LeafPurpose.CLIENT,
						BigInteger.valueOf(System.nanoTime()), Instant.now().minusSeconds(60),
						Instant.now().plusSeconds(3600)));
	}

	private PresenceHeartbeatResponse heartbeatWithCert(X509Certificate clientCert, PrivateKey clientKey,
			String nodeName, String gatewayAddr) {
		SslContext ssl = MtlsTestSupport.clientSslContext(caCertificate(), clientCert, clientKey);
		ManagedChannel channel = MtlsTestSupport.channel(grpcPort(), ssl);
		try {
			return PresenceGrpc.newBlockingStub(channel).heartbeat(
					PresenceHeartbeatRequest.newBuilder().setNodeName(nodeName).setGatewayAddr(gatewayAddr).build());
		} finally {
			shutdown(channel);
		}
	}

	private Node seedAgentNode() {
		ObjectNode labels = JSON.objectNode().put("env", "prod");
		return nodes.save(Node.create("web-" + unique(), null, labels, "agent", "active", null)).block();
	}

	// Health is layered: an anchorless node is unusable whatever presence says, so
	// a
	// test about presence has to give the node the enrollment anchor a registered
	// one
	// would have.
	private Node seedAnchoredAgentNode() {
		Node node = seedAgentNode();
		hostKeys.save(NodeHostKey.create(node.id(), "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp256 AAAA" + unique(),
				"SHA256:" + unique(), null, "pinned_key", null)).block();
		return node;
	}

	private static String unique() {
		return UUID.randomUUID().toString().substring(0, 8);
	}
}
