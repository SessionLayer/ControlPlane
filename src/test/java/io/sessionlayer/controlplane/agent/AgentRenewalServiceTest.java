package io.sessionlayer.controlplane.agent;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import io.sessionlayer.controlplane.audit.AuditEventStore;
import io.sessionlayer.controlplane.ca.mtls.InternalMtlsCaService;
import io.sessionlayer.controlplane.ca.mtls.LocalX509CaBackend;
import io.sessionlayer.controlplane.ca.mtls.X509CaBackend;
import io.sessionlayer.controlplane.ca.mtls.X509Certificates;
import io.sessionlayer.controlplane.data.runtime.AccessLock;
import io.sessionlayer.controlplane.data.runtime.AccessLockRepository;
import io.sessionlayer.controlplane.data.runtime.AgentIdentity;
import io.sessionlayer.controlplane.data.runtime.AgentIdentityRepository;
import io.sessionlayer.controlplane.data.runtime.AgentRenewalReceipt;
import io.sessionlayer.controlplane.data.runtime.AgentRenewalReceiptRepository;
import io.sessionlayer.controlplane.data.runtime.Node;
import io.sessionlayer.controlplane.grpc.LockFeedHub;
import io.sessionlayer.controlplane.mtls.MtlsTestSupport;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.transaction.reactive.TransactionalOperator;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;
import tools.jackson.databind.json.JsonMapper;

class AgentRenewalServiceTest {

	private static final UUID AGENT = UUID.randomUUID();
	private static final UUID NODE = UUID.randomUUID();

	private final InternalMtlsCaService mtlsCa = mock(InternalMtlsCaService.class);
	private final AgentIdentityRepository agentIdentities = mock(AgentIdentityRepository.class);
	private final io.sessionlayer.controlplane.data.runtime.NodeRepository nodes = mock(
			io.sessionlayer.controlplane.data.runtime.NodeRepository.class);
	private final AccessLockRepository accessLocks = mock(AccessLockRepository.class);
	private final LockFeedHub lockFeedHub = mock(LockFeedHub.class);
	private final AgentSecurityAlerts alerts = mock(AgentSecurityAlerts.class);
	private final AuditEventStore audit = mock(AuditEventStore.class);
	private final TransactionalOperator tx = mock(TransactionalOperator.class);
	private final AgentRenewalReceiptRepository renewalReceipts = mock(AgentRenewalReceiptRepository.class);

	private AgentRenewalService service;

	@BeforeEach
	@SuppressWarnings("unchecked")
	void setUp() {
		service = new AgentRenewalService(mtlsCa, agentIdentities, nodes, accessLocks, lockFeedHub, alerts,
				new AgentJoinProperties(), audit, tx, JsonMapper.builder().build(), renewalReceipts);
		when(audit.record(any(), any(), any(), any(), any(), any(), any())).thenReturn(Mono.empty());
		when(tx.transactional(any(Mono.class))).thenAnswer(inv -> inv.getArgument(0));
		when(renewalReceipts.findByAgentIdAndPriorGenerationAndCsrPublicKeyHash(any(),
				org.mockito.ArgumentMatchers.anyLong(), any())).thenReturn(Mono.empty());
		when(renewalReceipts.save(any())).thenAnswer(inv -> Mono.just(inv.getArgument(0)));
	}

	@Test
	void lockedIdentityIsRefusedWithoutIssuing() {
		when(agentIdentities.findById(AGENT)).thenReturn(Mono.just(identity("fp0", 0, "locked")));

		StepVerifier.create(service.renew(AGENT, "fp0", new byte[]{1}, 0)).verifyError(AgentJoinException.class);

		verify(agentIdentities, never()).save(any());
		verify(audit).record(any(), any(), eq("agent.renew"), eq("denied"), any(), any(), any());
	}

	@Test
	void fingerprintMissIsRefusedWithoutIssuing() {
		when(agentIdentities.findById(AGENT)).thenReturn(Mono.just(identity("fp0", 0, "active")));

		StepVerifier.create(service.renew(AGENT, "stale-or-stolen-fp", new byte[]{1}, 0))
				.verifyError(AgentJoinException.class);

		verify(agentIdentities, never()).save(any());
		verify(mtlsCa, never()).activeBackend();
	}

	@Test
	void generationMismatchAutoLocksNodeAndAlerts() {
		when(agentIdentities.findById(AGENT)).thenReturn(Mono.just(identity("fp0", 0, "active")));
		when(nodes.findById(NODE)).thenReturn(Mono.just(node("node-x")));
		when(agentIdentities.save(any())).thenAnswer(inv -> Mono.just(inv.getArgument(0)));
		when(accessLocks.save(any())).thenAnswer(inv -> Mono.just(inv.getArgument(0)));
		when(alerts.cloneDetected(any(), any(), org.mockito.ArgumentMatchers.anyLong(),
				org.mockito.ArgumentMatchers.anyLong())).thenReturn(Mono.empty());
		byte[] csr = MtlsTestSupport.csr(MtlsTestSupport.generateEcKeyPair(), "node-x");

		StepVerifier.create(service.renew(AGENT, "fp0", csr, 5))
				.verifyErrorSatisfies(e -> assertThat(((AgentJoinException) e).reason())
						.isEqualTo(AgentJoinException.Reason.FAILED_PRECONDITION));

		ArgumentCaptor<AgentIdentity> lockedIdentity = ArgumentCaptor.forClass(AgentIdentity.class);
		verify(agentIdentities).save(lockedIdentity.capture());
		assertThat(lockedIdentity.getValue().status()).isEqualTo("locked");
		assertThat(lockedIdentity.getValue().statusChangedBy()).isEqualTo("system:clone-detection");

		ArgumentCaptor<AccessLock> lock = ArgumentCaptor.forClass(AccessLock.class);
		verify(accessLocks).save(lock.capture());
		assertThat(lock.getValue().mode()).isEqualTo("strict");
		assertThat(lock.getValue().ttlSeconds()).isNull();
		assertThat(lock.getValue().expiresAt()).isNull();
		assertThat(lock.getValue().targetSelector().get("node_ids").get(0).stringValue()).isEqualTo(NODE.toString());
		// The lock must also name the agent IDENTITY: an agent peer is matched by its
		// agent id (URI SAN), never by the node UUID, so a node_ids-only selector could
		// not refuse the cloned agent's control channel at the Gateway.
		assertThat(lock.getValue().targetSelector().get("identities").get(0).stringValue()).isEqualTo(AGENT.toString());

		verify(lockFeedHub).publishAdded(any(AccessLock.class));
		verify(alerts).cloneDetected(AGENT, NODE, 0L, 5L);
		verify(audit).record(any(), any(), eq("agent.renew.generation_mismatch"), eq("failure"), any(), any(), any());
		verify(mtlsCa, never()).activeBackend();
	}

	// A lost or late RenewAgentIdentity response makes the Agent retry with the
	// SAME stale generation and CSR, which is otherwise indistinguishable from a
	// clone: locking there is a false positive and a permanent outage. The receipt
	// committed alongside the first renewal lets the identical retry replay the
	// already-issued cert instead.
	@Test
	void retryAfterCommittedRenewalReplaysInsteadOfLocking() {
		byte[] csr = MtlsTestSupport.csr(MtlsTestSupport.generateEcKeyPair(), "node-x");
		IssuedAgentIdentity first = performInitialRenewal(csr);
		assertThat(first.generation()).isEqualTo(1);

		// Captured post-hoc (not via a when()-time capture): setUp() already stubs
		// renewalReceipts.save(any()) generically, and re-stubbing it with a captor
		// mid-test would invoke that existing stub for real to register the new one,
		// answering with the captor's not-yet-captured (null) value -> NPE.
		ArgumentCaptor<AgentRenewalReceipt> receiptCaptor = ArgumentCaptor.forClass(AgentRenewalReceipt.class);
		verify(renewalReceipts).save(receiptCaptor.capture());
		AgentRenewalReceipt savedReceipt = receiptCaptor.getValue();

		when(agentIdentities.findById(AGENT)).thenReturn(Mono.just(new AgentIdentity(AGENT, NODE,
				"mtls:" + AGENT + ":1", "fp1", "fp0", 1, "token", "active", Instant.now(),
				Instant.now().plusSeconds(3600), null, null, null, 0L, Instant.now(), Instant.now())));
		when(renewalReceipts.findByAgentIdAndPriorGenerationAndCsrPublicKeyHash(AGENT, 0L,
				savedReceipt.csrPublicKeyHash())).thenReturn(Mono.just(savedReceipt));

		IssuedAgentIdentity retry = service.renew(AGENT, "fp0", csr, 0).block();

		assertThat(retry.generation()).isEqualTo(1);
		assertThat(retry.certificate()).isEqualTo(first.certificate());
		verify(alerts, never()).cloneDetected(any(), any(), org.mockito.ArgumentMatchers.anyLong(),
				org.mockito.ArgumentMatchers.anyLong());
		verify(lockFeedHub, never()).publishAdded(any());
		verify(agentIdentities, never())
				.save(org.mockito.ArgumentMatchers.argThat(saved -> "locked".equals(saved.status())));
	}

	// Clone detection must stay intact: a stale generation presented with a
	// DIFFERENT CSR key never matches the receipt (a clone holds its own keypair,
	// even when it authenticates with a stolen - still validly pinned -
	// certificate).
	@Test
	void staleGenerationWithDifferentCsrKeyStillLocksDespiteExistingReceipt() {
		byte[] legitCsr = MtlsTestSupport.csr(MtlsTestSupport.generateEcKeyPair(), "node-x");
		performInitialRenewal(legitCsr);

		when(agentIdentities.findById(AGENT)).thenReturn(Mono.just(new AgentIdentity(AGENT, NODE,
				"mtls:" + AGENT + ":1", "fp1", "fp0", 1, "token", "active", Instant.now(),
				Instant.now().plusSeconds(3600), null, null, null, 0L, Instant.now(), Instant.now())));
		when(accessLocks.save(any())).thenAnswer(inv -> Mono.just(inv.getArgument(0)));
		when(alerts.cloneDetected(any(), any(), org.mockito.ArgumentMatchers.anyLong(),
				org.mockito.ArgumentMatchers.anyLong())).thenReturn(Mono.empty());
		byte[] cloneCsr = MtlsTestSupport.csr(MtlsTestSupport.generateEcKeyPair(), "node-x");

		StepVerifier.create(service.renew(AGENT, "fp0", cloneCsr, 0))
				.verifyErrorSatisfies(e -> assertThat(((AgentJoinException) e).reason())
						.isEqualTo(AgentJoinException.Reason.FAILED_PRECONDITION));

		verify(alerts).cloneDetected(AGENT, NODE, 1L, 0L);
		verify(lockFeedHub).publishAdded(any());
	}

	private IssuedAgentIdentity performInitialRenewal(byte[] csr) {
		when(agentIdentities.findById(AGENT)).thenReturn(Mono.just(identity("fp0", 0, "active")));
		when(nodes.findById(NODE)).thenReturn(Mono.just(node("node-x")));
		when(mtlsCa.activeBackend()).thenReturn(Mono.just(testCaBackend()));
		when(agentIdentities.save(any())).thenAnswer(inv -> Mono.just(inv.getArgument(0)));
		return service.renew(AGENT, "fp0", csr, 0).block();
	}

	private static X509CaBackend testCaBackend() {
		KeyPair caKeys = MtlsTestSupport.generateEcKeyPair();
		Instant now = Instant.now();
		X509Certificate ca = X509Certificates.selfSignCa("test-ca", caKeys.getPublic(), caKeys.getPrivate(),
				BigInteger.ONE, now.minusSeconds(3600), now.plusSeconds(3600));
		return new LocalX509CaBackend(ca, caKeys.getPrivate());
	}

	private static AgentIdentity identity(String fingerprint, long generation, String status) {
		return new AgentIdentity(AGENT, NODE, "mtls:" + AGENT, fingerprint, null, generation, "token", status,
				Instant.now(), Instant.now().plusSeconds(3600), null, null, null, 0L, Instant.now(), Instant.now());
	}

	private static Node node(String name) {
		return new Node(NODE, name, null, JsonMapper.builder().build().createObjectNode(), "agent", "active", null,
				null, null, null, 0L, Instant.now(), Instant.now());
	}
}
