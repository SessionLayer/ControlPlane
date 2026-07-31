package io.sessionlayer.controlplane.agent;

import io.sessionlayer.controlplane.audit.AuditEventStore;
import io.sessionlayer.controlplane.ca.mtls.InternalMtlsCaService;
import io.sessionlayer.controlplane.ca.mtls.LeafCertificateSpec;
import io.sessionlayer.controlplane.ca.mtls.LeafPurpose;
import io.sessionlayer.controlplane.ca.mtls.Pkcs10Csrs;
import io.sessionlayer.controlplane.data.Uuids;
import io.sessionlayer.controlplane.data.runtime.AccessLock;
import io.sessionlayer.controlplane.data.runtime.AccessLockRepository;
import io.sessionlayer.controlplane.data.runtime.AgentIdentity;
import io.sessionlayer.controlplane.data.runtime.AgentIdentityRepository;
import io.sessionlayer.controlplane.data.runtime.AgentRenewalReceipt;
import io.sessionlayer.controlplane.data.runtime.AgentRenewalReceiptRepository;
import io.sessionlayer.controlplane.data.runtime.Node;
import io.sessionlayer.controlplane.data.runtime.NodeRepository;
import io.sessionlayer.controlplane.grpc.LockFeedHub;
import io.sessionlayer.controlplane.mtls.AgentIdentityUri;
import io.sessionlayer.controlplane.mtls.CertificateFingerprints;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.time.Instant;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.springframework.dao.OptimisticLockingFailureException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.reactive.TransactionalOperator;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.node.ArrayNode;
import tools.jackson.databind.node.ObjectNode;

@Service
public class AgentRenewalService {

	private static final String CLONE_REASON = "generation mismatch (possible credential clone)";
	private static final String CLONE_ACTOR = "system:clone-detection";

	private final InternalMtlsCaService mtlsCa;
	private final AgentIdentityRepository agentIdentities;
	private final NodeRepository nodes;
	private final AccessLockRepository accessLocks;
	private final LockFeedHub lockFeedHub;
	private final AgentSecurityAlerts alerts;
	private final AgentJoinProperties properties;
	private final AuditEventStore audit;
	private final TransactionalOperator tx;
	private final ObjectMapper objectMapper;
	private final AgentRenewalReceiptRepository renewalReceipts;

	public AgentRenewalService(InternalMtlsCaService mtlsCa, AgentIdentityRepository agentIdentities,
			NodeRepository nodes, AccessLockRepository accessLocks, LockFeedHub lockFeedHub, AgentSecurityAlerts alerts,
			AgentJoinProperties properties, AuditEventStore audit, TransactionalOperator tx, ObjectMapper objectMapper,
			AgentRenewalReceiptRepository renewalReceipts) {
		this.mtlsCa = mtlsCa;
		this.agentIdentities = agentIdentities;
		this.nodes = nodes;
		this.accessLocks = accessLocks;
		this.lockFeedHub = lockFeedHub;
		this.alerts = alerts;
		this.properties = properties;
		this.audit = audit;
		this.tx = tx;
		this.objectMapper = objectMapper;
		this.renewalReceipts = renewalReceipts;
	}

	public Mono<IssuedAgentIdentity> renew(UUID callerAgentId, String presentedFingerprint, byte[] csrDer,
			long currentGeneration) {
		if (callerAgentId == null) {
			return Mono.error(unauthenticated());
		}
		return agentIdentities.findById(callerAgentId).switchIfEmpty(Mono.error(unauthenticated()))
				.flatMap(identity -> renewFor(identity, presentedFingerprint, csrDer, currentGeneration));
	}

	private Mono<IssuedAgentIdentity> renewFor(AgentIdentity identity, String presentedFingerprint, byte[] csrDer,
			long currentGeneration) {
		if (!"active".equals(identity.status())) {
			return denied(identity, "inactive");
		}
		if (!fingerprintPins(identity, presentedFingerprint)) {
			return denied(identity, "fingerprint_mismatch");
		}
		return nodes.findById(identity.nodeId()).switchIfEmpty(Mono.error(unauthenticated()))
				.flatMap(node -> renewForNode(identity, node, csrDer, currentGeneration));
	}

	private Mono<IssuedAgentIdentity> renewForNode(AgentIdentity identity, Node node, byte[] csrDer,
			long currentGeneration) {
		Pkcs10Csrs.ParsedCsr csr;
		try {
			csr = Pkcs10Csrs.parseAndVerify(csrDer);
		} catch (Pkcs10Csrs.CsrException e) {
			return Mono.error(new AgentJoinException(AgentJoinException.Reason.INVALID_ARGUMENT, "invalid CSR"));
		}
		if (!node.name().equals(csr.commonName())) {
			return Mono.error(new AgentJoinException(AgentJoinException.Reason.INVALID_ARGUMENT,
					"CSR subject does not match identity"));
		}
		String csrPublicKeyHash = csrPublicKeyHash(csr.publicKey());
		if (currentGeneration != identity.generation()) {
			return autoLock(identity.id(), identity.nodeId(), identity.generation(), currentGeneration,
					csrPublicKeyHash);
		}
		long newGeneration = identity.generation() + 1;
		return mtlsCa.activeBackend().flatMap(backend -> {
			Instant now = Instant.now();
			Instant notBefore = now.minus(properties.getCertBackdate());
			Instant notAfter = now.plus(properties.getIdentityCertTtl());
			return Mono
					.fromCallable(() -> backend.issueLeaf(new LeafCertificateSpec(csr.publicKey(), node.name(),
							List.of(node.name()), List.of(AgentIdentityUri.of(identity.id())), LeafPurpose.CLIENT,
							AgentCertificates.serial(Uuids.v7()), notBefore, notAfter)))
					.subscribeOn(Schedulers.boundedElastic()).flatMap(leaf -> {
						String fingerprint = CertificateFingerprints.sha256Hex(leaf);
						AgentIdentity renewed = new AgentIdentity(identity.id(), identity.nodeId(),
								"mtls:" + identity.id() + ":" + newGeneration, fingerprint, identity.fingerprint(),
								newGeneration, identity.joinMethod(), identity.status(), notBefore, notAfter,
								identity.statusReason(), identity.statusChangedBy(), identity.statusChangedAt(),
								identity.version(), identity.createdAt(), identity.updatedAt());
						IssuedAgentIdentity issued = AgentCertificates.toIssued(leaf, backend, identity.id(),
								identity.nodeId(), newGeneration, notBefore, notAfter);
						// A receipt is committed alongside the generation bump (same transaction) so a
						// lost-response retry can never observe the advanced generation without it.
						// caChain().get(0): AgentCertificates.toIssued currently always returns a
						// single-entry chain (the one active CA); revisit if that ever changes.
						AgentRenewalReceipt receipt = AgentRenewalReceipt.create(identity.id(), currentGeneration,
								csrPublicKeyHash, newGeneration, issued.certificate(), issued.caChain().get(0),
								notBefore, notAfter, now.plus(properties.getRenewalReceiptTtl()));
						Mono<IssuedAgentIdentity> committed = tx
								.transactional(agentIdentities.save(renewed).then(renewalReceipts.save(receipt))
										.then(audit.record(node.name(), identity.id().toString(), "agent.renew",
												"success", null, identity.nodeId(), Map.of("generation",
														Long.toString(newGeneration), "fingerprint", fingerprint)))
										.thenReturn(issued));
						return committed.onErrorResume(OptimisticLockingFailureException.class,
								race -> autoLock(identity.id(), identity.nodeId(), identity.generation(),
										currentGeneration, csrPublicKeyHash));
					});
		});
	}

	/**
	 * A stale generation is either a replay of a call the CP already completed (the
	 * Agent's response was lost/late and it retried with the same CSR) or a genuine
	 * clone racing the old generation. A clone cannot reproduce the CSR key — it
	 * holds its own keypair — so a matching, unexpired receipt for this exact
	 * (agent, prior generation, CSR key) is proof of the former: replay it instead
	 * of locking.
	 */
	private Mono<IssuedAgentIdentity> autoLock(UUID agentId, UUID nodeId, long expectedGeneration,
			long presentedGeneration, String csrPublicKeyHash) {
		Instant now = Instant.now();
		return renewalReceipts
				.findByAgentIdAndPriorGenerationAndCsrPublicKeyHash(agentId, presentedGeneration, csrPublicKeyHash)
				.filter(receipt -> receipt.expiresAt().isAfter(now)).map(receipt -> toIssued(receipt, nodeId))
				.switchIfEmpty(
						Mono.defer(() -> lockAndAlert(agentId, nodeId, expectedGeneration, presentedGeneration)));
	}

	private static IssuedAgentIdentity toIssued(AgentRenewalReceipt receipt, UUID nodeId) {
		return new IssuedAgentIdentity(receipt.certificate(), List.of(receipt.caCertificate()), receipt.agentId(),
				nodeId, receipt.newGeneration(), receipt.notBefore().getEpochSecond(),
				receipt.notAfter().getEpochSecond());
	}

	private Mono<IssuedAgentIdentity> lockAndAlert(UUID agentId, UUID nodeId, long expectedGeneration,
			long presentedGeneration) {
		Instant now = Instant.now();
		Map<String, String> detail = Map.of("expected", Long.toString(expectedGeneration), "presented",
				Long.toString(presentedGeneration));
		Mono<AccessLock> committed = tx.transactional(agentIdentities.findById(agentId).flatMap(fresh -> {
			AccessLock lock = AccessLock.create(cloneLockSelector(nodeId, agentId), "strict", null, null, CLONE_REASON,
					CLONE_ACTOR);
			Mono<AccessLock> lockCreate = accessLocks.save(lock)
					.flatMap(saved -> audit.record(CLONE_ACTOR, agentId.toString(), "agent.renew.generation_mismatch",
							"failure", null, nodeId, detail).thenReturn(saved));
			return "active".equals(fresh.status())
					? agentIdentities.save(lockedCopy(fresh, now)).then(lockCreate)
					: Mono.empty();
		}));
		return committed.flatMap(lock -> {
			lockFeedHub.publishAdded(lock);
			return alerts.cloneDetected(agentId, nodeId, expectedGeneration, presentedGeneration);
		}).then(Mono.error(generationMismatch()));
	}

	private static String csrPublicKeyHash(PublicKey publicKey) {
		try {
			byte[] digest = MessageDigest.getInstance("SHA-256").digest(publicKey.getEncoded());
			return HexFormat.of().formatHex(digest);
		} catch (NoSuchAlgorithmException impossible) {
			throw new IllegalStateException(impossible);
		}
	}

	private static AgentIdentity lockedCopy(AgentIdentity fresh, Instant now) {
		return new AgentIdentity(fresh.id(), fresh.nodeId(), fresh.mtlsIdentityRef(), fresh.fingerprint(),
				fresh.prevFingerprint(), fresh.generation(), fresh.joinMethod(), "locked", fresh.issuedAt(),
				fresh.notAfter(), CLONE_REASON, CLONE_ACTOR, now, fresh.version(), fresh.createdAt(),
				fresh.updatedAt());
	}

	private ObjectNode cloneLockSelector(UUID nodeId, UUID agentId) {
		ObjectNode selector = objectMapper.createObjectNode();
		ArrayNode nodeIds = selector.putArray("node_ids");
		nodeIds.add(nodeId.toString());
		ArrayNode identities = selector.putArray("identities");
		identities.add(agentId.toString());
		return selector;
	}

	private static boolean fingerprintPins(AgentIdentity identity, String presented) {
		return presented != null
				&& (presented.equals(identity.fingerprint()) || presented.equals(identity.prevFingerprint()));
	}

	// Audit the fail-closed denial (generic to the client, specific reason
	// server-side).
	private Mono<IssuedAgentIdentity> denied(AgentIdentity identity, String reason) {
		return audit
				.record(identity.id().toString(), identity.id().toString(), "agent.renew", "denied", null,
						identity.nodeId(), Map.of("reason", reason))
				.then(Mono
						.error(new AgentJoinException(AgentJoinException.Reason.PERMISSION_DENIED, "renewal refused")));
	}

	private static AgentJoinException unauthenticated() {
		return new AgentJoinException(AgentJoinException.Reason.UNAUTHENTICATED, "agent identity unknown");
	}

	private static AgentJoinException generationMismatch() {
		return new AgentJoinException(AgentJoinException.Reason.FAILED_PRECONDITION,
				"generation mismatch (renewal refused)");
	}
}
