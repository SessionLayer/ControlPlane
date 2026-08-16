package io.sessionlayer.controlplane.agent;

import io.sessionlayer.controlplane.audit.AuditEventStore;
import io.sessionlayer.controlplane.authz.LockMatching;
import io.sessionlayer.controlplane.ca.mtls.InternalMtlsCaService;
import io.sessionlayer.controlplane.ca.mtls.LeafCertificateSpec;
import io.sessionlayer.controlplane.ca.mtls.LeafPurpose;
import io.sessionlayer.controlplane.ca.mtls.Pkcs10Csrs;
import io.sessionlayer.controlplane.data.Uuids;
import io.sessionlayer.controlplane.data.runtime.AccessLock;
import io.sessionlayer.controlplane.data.runtime.AccessLockRepository;
import io.sessionlayer.controlplane.data.runtime.AgentIdentity;
import io.sessionlayer.controlplane.data.runtime.AgentIdentityRepository;
import io.sessionlayer.controlplane.data.runtime.Node;
import io.sessionlayer.controlplane.data.runtime.NodeRepository;
import io.sessionlayer.controlplane.grpc.v1.EnrollAgentRequest;
import io.sessionlayer.controlplane.mtls.AgentIdentityUri;
import io.sessionlayer.controlplane.mtls.CertificateFingerprints;
import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

@Service
public class AgentEnrollmentService {

	private final AgentJoinTokenService tokenJoin;
	private final OidcJoinVerifier oidcJoin;
	private final MtlsJoinVerifier mtlsJoin;
	private final InternalMtlsCaService mtlsCa;
	private final AgentIdentityRepository agentIdentities;
	private final NodeRepository nodes;
	private final AccessLockRepository accessLocks;
	private final AgentJoinProperties properties;
	private final AuditEventStore audit;
	private final ObjectMapper objectMapper;

	public AgentEnrollmentService(AgentJoinTokenService tokenJoin, OidcJoinVerifier oidcJoin, MtlsJoinVerifier mtlsJoin,
			InternalMtlsCaService mtlsCa, AgentIdentityRepository agentIdentities, NodeRepository nodes,
			AccessLockRepository accessLocks, AgentJoinProperties properties, AuditEventStore audit,
			ObjectMapper objectMapper) {
		this.tokenJoin = tokenJoin;
		this.oidcJoin = oidcJoin;
		this.mtlsJoin = mtlsJoin;
		this.mtlsCa = mtlsCa;
		this.agentIdentities = agentIdentities;
		this.nodes = nodes;
		this.accessLocks = accessLocks;
		this.properties = properties;
		this.audit = audit;
		this.objectMapper = objectMapper;
	}

	public Mono<IssuedAgentIdentity> enroll(EnrollAgentRequest request) {
		String nodeName = request.getNodeName();
		if (!AgentNodeNames.isValid(nodeName)) {
			return Mono.error(new AgentJoinException(AgentJoinException.Reason.INVALID_ARGUMENT, "invalid node_name"));
		}
		byte[] csrDer = request.getPkcs10Csr().toByteArray();
		String joinMethod = joinMethod(request);
		if (joinMethod == null) {
			return denied(nodeName, "no_proof", AgentJoinException.Reason.UNAUTHENTICATED);
		}
		return verifyProof(request, joinMethod, nodeName, csrDer).then(Mono.defer(() -> resolveNode(nodeName)))
				.flatMap(node -> refuseIfLocked(node).then(refuseIfActive(node.id(), nodeName))
						.then(Mono.fromCallable(() -> parseCsr(csrDer, nodeName))
								.subscribeOn(Schedulers.boundedElastic()))
						.flatMap(csr -> consumeIfToken(request, joinMethod, nodeName)
								.then(issue(nodeName, node.id(), joinMethod, csr))));
	}

	private Mono<Void> verifyProof(EnrollAgentRequest request, String joinMethod, String nodeName, byte[] csrDer) {
		return switch (joinMethod) {
			case "token" -> tokenJoin.isValid(request.getToken().getJoinToken(), nodeName)
					.flatMap(valid -> valid ? Mono.<Void>empty() : denied(nodeName, "invalid_token").then());
			case "oidc" -> oidcJoin.verify(request.getOidc().getWorkloadToken(), nodeName);
			case "mtls" -> mtlsJoin.verify(request.getMtls().getOperatorCertificate().toByteArray(),
					request.getMtls().getPopSignature().toByteArray(), nodeName, csrDer);
			default -> denied(nodeName, "no_proof", AgentJoinException.Reason.UNAUTHENTICATED).then();
		};
	}

	private Mono<Node> resolveNode(String nodeName) {
		return nodes.findByName(nodeName).flatMap(this::requireAgentConnector)
				.switchIfEmpty(Mono.defer(() -> nodes
						.save(Node.create(nodeName, null, objectMapper.createObjectNode(), "agent", "active", null))
						.onErrorResume(DataIntegrityViolationException.class,
								race -> nodes.findByName(nodeName).flatMap(this::requireAgentConnector))));
	}

	// An Agent attached to an agentless-registered node leaves the authorizer
	// telling the Gateway to dial that node's address directly, so the control
	// channel the Agent just opened is never used. Refuse the join and make the
	// operator fix the registration.
	private Mono<Node> requireAgentConnector(Node node) {
		return "agent".equals(node.connectorKind())
				? Mono.just(node)
				: denied(node.name(), "node_not_agent_connector", AgentJoinException.Reason.PERMISSION_DENIED);
	}

	private Mono<Void> refuseIfLocked(Node node) {
		Instant now = Instant.now();
		LockMatching.LockSubject subject = new LockMatching.LockSubject(null, node.id().toString(), labels(node),
				Set.of(), null, Set.of());
		return accessLocks.findAll().filter(lock -> unexpired(lock, now))
				.filter(lock -> LockMatching.matches(lock.targetSelector(), subject)).next()
				.flatMap(lock -> denied(node.name(), "node_locked", AgentJoinException.Reason.PERMISSION_DENIED))
				.then();
	}

	private Mono<Void> refuseIfActive(UUID nodeId, String nodeName) {
		return agentIdentities.findByNodeIdAndStatus(nodeId, "active")
				.flatMap(existing -> denied(nodeName, "already_enrolled", AgentJoinException.Reason.PERMISSION_DENIED))
				.then();
	}

	private Mono<Void> consumeIfToken(EnrollAgentRequest request, String joinMethod, String nodeName) {
		return "token".equals(joinMethod)
				? tokenJoin.consume(request.getToken().getJoinToken(), nodeName).then()
				: Mono.empty();
	}

	private Mono<IssuedAgentIdentity> issue(String nodeName, UUID nodeId, String joinMethod, Pkcs10Csrs.ParsedCsr csr) {
		return mtlsCa.activeBackend().flatMap(backend -> {
			UUID agentId = Uuids.v7();
			Instant now = Instant.now();
			Instant notBefore = now.minus(properties.getCertBackdate());
			Instant notAfter = now.plus(properties.getIdentityCertTtl());
			return Mono
					.fromCallable(() -> backend.issueLeaf(new LeafCertificateSpec(csr.publicKey(), nodeName,
							List.of(nodeName), List.of(AgentIdentityUri.of(agentId)), LeafPurpose.CLIENT,
							AgentCertificates.serial(Uuids.v7()), notBefore, notAfter)))
					.subscribeOn(Schedulers.boundedElastic()).flatMap(leaf -> {
						String fingerprint = CertificateFingerprints.sha256Hex(leaf);
						AgentIdentity identity = new AgentIdentity(agentId, nodeId, "mtls:" + agentId, fingerprint,
								null, 0L, joinMethod, "active", notBefore, notAfter, null, null, null, null, null,
								null);
						return agentIdentities.save(identity)
								.onErrorMap(DataIntegrityViolationException.class,
										race -> new AgentJoinException(AgentJoinException.Reason.PERMISSION_DENIED,
												"enrollment refused"))
								.then(audit.record(nodeName, agentId.toString(), "agent.enroll", "success", null,
										nodeId,
										Map.of("generation", "0", "fingerprint", fingerprint, "join_method",
												joinMethod)))
								.thenReturn(AgentCertificates.toIssued(leaf, backend, agentId, nodeId, 0L, notBefore,
										notAfter));
					});
		});
	}

	private static String joinMethod(EnrollAgentRequest request) {
		return switch (request.getProofCase()) {
			case TOKEN -> "token";
			case OIDC -> "oidc";
			case MTLS -> "mtls";
			default -> null;
		};
	}

	private static Pkcs10Csrs.ParsedCsr parseCsr(byte[] csrDer, String nodeName) {
		Pkcs10Csrs.ParsedCsr csr;
		try {
			csr = Pkcs10Csrs.parseAndVerify(csrDer);
		} catch (Pkcs10Csrs.CsrException e) {
			throw new AgentJoinException(AgentJoinException.Reason.INVALID_ARGUMENT, "invalid CSR");
		}
		if (!nodeName.equals(csr.commonName())) {
			throw new AgentJoinException(AgentJoinException.Reason.INVALID_ARGUMENT,
					"CSR subject does not match node_name");
		}
		return csr;
	}

	private Map<String, String> labels(Node node) {
		Map<String, String> labels = new HashMap<>();
		JsonNode resolved = node.resolvedLabels();
		if (resolved != null && resolved.isObject()) {
			resolved.properties().forEach(entry -> {
				if (entry.getValue().isString()) {
					labels.put(entry.getKey(), entry.getValue().stringValue());
				}
			});
		}
		return labels;
	}

	private static boolean unexpired(AccessLock lock, Instant now) {
		return lock.expiresAt() == null || lock.expiresAt().isAfter(now);
	}

	private <T> Mono<T> denied(String nodeName, String reason) {
		return denied(nodeName, reason, AgentJoinException.Reason.UNAUTHENTICATED);
	}

	private <T> Mono<T> denied(String nodeName, String reason, AgentJoinException.Reason category) {
		return audit.record(nodeName, nodeName, "agent.enroll", "denied", null, null, Map.of("reason", reason))
				.then(Mono.error(new AgentJoinException(category, "enrollment refused")));
	}
}
