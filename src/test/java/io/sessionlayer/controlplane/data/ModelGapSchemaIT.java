package io.sessionlayer.controlplane.data;

import static org.assertj.core.api.Assertions.assertThat;

import io.sessionlayer.controlplane.data.config.OperatorSettings;
import io.sessionlayer.controlplane.data.config.OperatorSettingsRepository;
import io.sessionlayer.controlplane.data.config.PolicyEpoch;
import io.sessionlayer.controlplane.data.config.PolicyEpochRepository;
import io.sessionlayer.controlplane.data.config.SessionLimitPolicy;
import io.sessionlayer.controlplane.data.config.SessionLimitPolicyRepository;
import io.sessionlayer.controlplane.data.runtime.DeviceFlow;
import io.sessionlayer.controlplane.data.runtime.DeviceFlowRepository;
import io.sessionlayer.controlplane.data.runtime.Node;
import io.sessionlayer.controlplane.data.runtime.NodeHostKey;
import io.sessionlayer.controlplane.data.runtime.NodeHostKeyRepository;
import io.sessionlayer.controlplane.data.runtime.NodeRepository;
import io.sessionlayer.controlplane.data.runtime.ServiceAccountCredential;
import io.sessionlayer.controlplane.data.runtime.ServiceAccountCredentialRepository;
import io.sessionlayer.controlplane.data.runtime.SessionLease;
import io.sessionlayer.controlplane.data.runtime.SessionLeaseRepository;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.r2dbc.core.DatabaseClient;
import reactor.test.StepVerifier;
import tools.jackson.databind.ObjectMapper;

class ModelGapSchemaIT extends AbstractDataIT {

	@Autowired
	private OperatorSettingsRepository operatorSettings;
	@Autowired
	private PolicyEpochRepository policyEpochs;
	@Autowired
	private SessionLimitPolicyRepository sessionLimits;
	@Autowired
	private ServiceAccountCredentialRepository saCreds;
	@Autowired
	private DeviceFlowRepository deviceFlows;
	@Autowired
	private NodeHostKeyRepository hostKeys;
	@Autowired
	private SessionLeaseRepository leases;
	@Autowired
	private NodeRepository nodes;
	@Autowired
	private DatabaseClient db;
	@Autowired
	private ObjectMapper objectMapper;

	private boolean columnExists(String schema, String table, String column) {
		return Boolean.TRUE.equals(db
				.sql("SELECT EXISTS (SELECT 1 FROM information_schema.columns "
						+ "WHERE table_schema = :s AND table_name = :t AND column_name = :c)")
				.bind("s", schema).bind("t", table).bind("c", column).map(row -> row.get(0, Boolean.class)).one()
				.block());
	}

	@Test
	void allExpectedTablesAndColumnsExist() {
		Map<String, String> newTables = Map.of("config", "operator_settings", "config#2", "policy_epoch", "config#3",
				"session_limit_policy", "runtime", "service_account_credential", "runtime#2", "device_flow",
				"runtime#3", "node_host_key", "runtime#4", "session_lease");
		newTables.forEach((k, table) -> {
			String schema = k.startsWith("config") ? "config" : "runtime";
			assertThat(columnExists(schema, table, "id")).as("table %s.%s exists", schema, table).isTrue();
		});
		assertThat(columnExists("runtime", "recording_ref", "retention_until")).isTrue();
		assertThat(columnExists("runtime", "recording_ref", "legal_hold")).isTrue();
		assertThat(columnExists("runtime", "recording_ref", "status")).isTrue();
		assertThat(columnExists("runtime", "recording_ref", "content_digest")).isTrue();
		assertThat(columnExists("runtime", "node", "status_reason")).isTrue();
		assertThat(columnExists("runtime", "node", "status_changed_by")).isTrue();
		assertThat(columnExists("runtime", "agent_identity", "status_reason")).isTrue();
		assertThat(columnExists("runtime", "gateway_identity", "status_reason")).isTrue();
		assertThat(columnExists("runtime", "jit_request", "decided_by")).isTrue();
		assertThat(columnExists("runtime", "jit_request", "decision_reason")).isTrue();
	}

	@Test
	void operatorSettingsSingletonRoundTripsAndRejectsSecondRow() {
		var saved = operatorSettings.save(OperatorSettings.defaults()).block();
		assertThat(saved.auditRetentionDays()).isEqualTo(365);
		assertThat(saved.defaultWormMode()).isEqualTo("governance");
		assertThat(operatorSettings.findSingleton().block()).isNotNull();
		StepVerifier.create(operatorSettings.save(OperatorSettings.defaults()))
				.verifyError(DataIntegrityViolationException.class);
	}

	@Test
	void policyEpochRoundTripsAndIsMonotonic() {
		var epoch = policyEpochs.save(PolicyEpoch.initial()).block();
		var bumped = policyEpochs.save(new PolicyEpoch(epoch.id(), true, 5L, epoch.version(), null)).block();
		assertThat(bumped.epoch()).isEqualTo(5L);
		StepVerifier.create(policyEpochs.save(new PolicyEpoch(bumped.id(), true, 3L, bumped.version(), null)))
				.verifyError(DataIntegrityViolationException.class);
	}

	@Test
	void sessionLimitPolicyRoundTrips() {
		var sel = objectMapper.readTree("{\"group\":\"contractors\"}");
		var reread = sessionLimits.save(SessionLimitPolicy.create("contractors", sel, 2, 3600, 600, "api"))
				.flatMap(s -> sessionLimits.findById(s.id())).block();
		assertThat(reread.maxConcurrentSessions()).isEqualTo(2);
		assertThat(reread.identitySelector()).isEqualTo(sel);
	}

	@Test
	void serviceAccountCredentialRoundTripsAndRejectsPemSecret() {
		var reread = saCreds
				.save(ServiceAccountCredential.create(UUID.randomUUID(), "ci-bot", "client_secret", "argon2:abc",
						"SHA256:fp", Instant.now(), Instant.now().plus(1, ChronoUnit.DAYS)))
				.flatMap(s -> saCreds.findById(s.id())).block();
		assertThat(reread.status()).isEqualTo("active");
		StepVerifier
				.create(saCreds.save(ServiceAccountCredential.create(UUID.randomUUID(), "bad", "client_secret",
						"-----BEGIN PRIVATE KEY-----", null, Instant.now(), null)))
				.verifyError(DataIntegrityViolationException.class);
	}

	@Test
	void deviceFlowRoundTrips() {
		var reread = deviceFlows
				.save(DeviceFlow.create("dh", "uh", "conn-1", "203.0.113.4", 5,
						Instant.now().plus(10, ChronoUnit.MINUTES)))
				.flatMap(s -> deviceFlows.findByDeviceCodeHash("dh")).block();
		assertThat(reread.status()).isEqualTo("pending");
		assertThat(reread.connectionBinding()).isEqualTo("conn-1");
	}

	@Test
	void nodeHostKeyRoundTripsAndRejectsPrivateKey() {
		var node = nodes.save(Node.create("hk-node", null, obj(), "agentless", "active", "10.0.0.5")).block();
		var reread = hostKeys.save(NodeHostKey.create(node.id(), "ssh-ed25519", "ssh-ed25519 AAAAC3Nz...", "SHA256:hk",
				null, "pinned_key", Instant.now())).flatMap(k -> hostKeys.findByNodeId(node.id()).next()).block();
		assertThat(reread.source()).isEqualTo("pinned_key");
		StepVerifier
				.create(hostKeys.save(NodeHostKey.create(node.id(), "ssh-ed25519", "-----BEGIN PRIVATE KEY-----",
						"SHA256:bad", null, "pinned_key", Instant.now())))
				.verifyError(DataIntegrityViolationException.class);
	}

	// The certificate anchor the documentation calls PRIMARY: a certificate type
	// token, and neither a public key nor a fingerprint, because its trust is the
	// CA signature. The schema was shaped for the pinned-key case and rejected all
	// three, so this row could not exist.
	@Test
	void aHostCaAnchorStoresACertificateWithNoKeyOrFingerprint() {
		var node = nodes.save(Node.create("hk-cert-node", null, obj(), "agentless", "active", "10.0.0.6")).block();
		var reread = hostKeys
				.save(NodeHostKey.create(node.id(), "ssh-ed25519-cert-v01@openssh.com", null, null,
						"ssh-ed25519-cert-v01@openssh.com AAAAIHNz... host@example", "host_ca", null))
				.flatMap(k -> hostKeys.findByNodeId(node.id()).next()).block();
		assertThat(reread.source()).isEqualTo("host_ca");
		assertThat(reread.publicKey()).isNull();
		assertThat(reread.fingerprint()).isNull();
	}

	// Relaxing those columns must not become a licence for a pinned key without
	// one: a pinned_key row IS its public key and the fingerprint an operator
	// compares, so the old guarantee still holds exactly where it applies.
	@Test
	void aPinnedKeyAnchorStillRequiresItsKeyAndFingerprint() {
		var node = nodes.save(Node.create("hk-pin-node", null, obj(), "agentless", "active", "10.0.0.7")).block();
		StepVerifier.create(hostKeys.save(NodeHostKey.create(node.id(), "ssh-ed25519", "ssh-ed25519 AAAAC3Nz...", null,
				null, "pinned_key", null))).verifyError(DataIntegrityViolationException.class);
		StepVerifier
				.create(hostKeys.save(
						NodeHostKey.create(node.id(), "ssh-ed25519", null, "SHA256:hk", null, "pinned_key", null)))
				.verifyError(DataIntegrityViolationException.class);
	}

	// An all-null host_ca row anchors nothing; and the same certificate must not be
	// recorded twice for one node, which UNIQUE (node_id, fingerprint) stopped
	// constraining the moment fingerprints became nullable.
	@Test
	void aHostCaAnchorMustCarryMaterialAndIsRecordedOnce() {
		var node = nodes.save(Node.create("hk-ca-guard", null, obj(), "agentless", "active", "10.0.0.8")).block();
		StepVerifier.create(hostKeys.save(
				NodeHostKey.create(node.id(), "ssh-ed25519-cert-v01@openssh.com", null, null, null, "host_ca", null)))
				.verifyError(DataIntegrityViolationException.class);

		String certLine = "ssh-ed25519-cert-v01@openssh.com AAAAIHNzZHVw... host@example";
		hostKeys.save(NodeHostKey.create(node.id(), "ssh-ed25519-cert-v01@openssh.com", null, null, certLine, "host_ca",
				null)).block();
		StepVerifier.create(hostKeys.save(NodeHostKey.create(node.id(), "ssh-ed25519-cert-v01@openssh.com", null, null,
				certLine, "host_ca", null))).verifyError(DataIntegrityViolationException.class);
	}

	@Test
	void sessionLeaseConcurrencyCounts() {
		String identity = "conc-" + UUID.randomUUID();
		leases.save(SessionLease.acquire(identity, null, "gw-a", Instant.now(), null)).block();
		leases.save(SessionLease.acquire(identity, null, "gw-b", Instant.now(), null)).block();
		var released = leases.save(SessionLease.acquire(identity, null, "gw-c", Instant.now(), null)).block();
		leases.save(new SessionLease(released.id(), released.identity(), released.sessionId(), released.gatewayName(),
				released.acquiredAt(), released.expiresAt(), Instant.now(), released.version(), released.createdAt(),
				released.updatedAt())).block();
		assertThat(leases.countLiveByIdentity(identity, Instant.now()).block()).isEqualTo(2L);
	}

	@Test
	void recordingRetentionColumnsRoundTrip() {
		assertThat(columnExists("runtime", "recording_ref", "format")).isTrue();
	}

	private tools.jackson.databind.JsonNode obj() {
		return objectMapper.readTree("{}");
	}
}
