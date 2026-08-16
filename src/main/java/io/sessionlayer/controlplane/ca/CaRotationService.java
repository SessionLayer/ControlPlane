package io.sessionlayer.controlplane.ca;

import io.sessionlayer.controlplane.data.config.CaConfig;
import io.sessionlayer.controlplane.data.config.CaConfigRepository;
import io.sessionlayer.controlplane.data.runtime.CaKeyMaterialRepository;
import java.time.Duration;
import java.util.List;
import java.util.Set;
import java.util.concurrent.TimeoutException;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.reactive.TransactionalOperator;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

/**
 * CA rotation without fleet downtime: overlap-then-drain over
 * {@code ca_config.rotation_state} ({@code incoming → active → outgoing →
 * expired}) with the partial-unique active-per-kind index as a backstop. During
 * an overlap the trusted set (what nodes trust via {@code TrustedUserCAKeys})
 * contains the incoming (pre-published), active and outgoing CA keys, so no
 * in-flight or new session is rejected; {@code expired} keys drop out of trust.
 */
@Service
public class CaRotationService {

	private static final Set<String> TRUSTED_STATES = Set.of("incoming", "active", "outgoing");

	private final CaConfigRepository caConfigs;
	private final CaKeyMaterialRepository caKeyMaterials;
	private final LocalCaFactory localCaFactory;
	private final List<CaKeyProvisioner> provisioners;
	private final TransactionalOperator tx;
	private final Duration provisionTimeout;

	public CaRotationService(CaConfigRepository caConfigs, CaKeyMaterialRepository caKeyMaterials,
			LocalCaFactory localCaFactory, List<CaKeyProvisioner> provisioners, TransactionalOperator tx,
			@Value("${sessionlayer.ca.provision-timeout:PT10S}") Duration provisionTimeout) {
		this.caConfigs = caConfigs;
		this.caKeyMaterials = caKeyMaterials;
		this.localCaFactory = localCaFactory;
		this.provisioners = provisioners;
		this.tx = tx;
		this.provisionTimeout = provisionTimeout;
	}

	/**
	 * No {@link CaKeyProvisioner} is registered for the requested backend in this
	 * build. Distinct from {@link CaBackendCapabilities.BackendNotImplemented}: a
	 * backend can be a capable signer while this build's bean wiring has no
	 * provisioner for it, and rotation must refuse just as hard either way —
	 * rotation refuses rather than provisioning anywhere else, because a CA the
	 * operator believes is in a key service must never get a database key by
	 * fallback.
	 */
	public static final class NoProvisionerForBackend extends RuntimeException {
		public NoProvisionerForBackend(String backend) {
			super("'" + backend + "' is not configured on this Control Plane: no CA key provisioner is wired for "
					+ "it in this build. Configure the backend before rotating onto it.");
		}
	}

	/**
	 * A {@link CaKeyProvisioner} did not complete within {@link #provisionTimeout}
	 * ({@code sessionlayer.ca.provision-timeout}). The HTTP client's own
	 * connect/response timeouts are not sufficient alone — a stalled connection
	 * between response headers and body can outlive them, and a provisioner need
	 * not be an HTTP client at all — so this is an independent wall-clock bound
	 * across every backend. Fails closed, naming the key reference rather than
	 * surfacing a bare {@link TimeoutException}.
	 */
	public static final class ProvisionTimedOut extends RuntimeException {
		public ProvisionTimedOut(String backend, String caKind) {
			super("provisioning a '" + backend + "' CA key for the '" + caKind + "' kind did not complete within "
					+ "sessionlayer.ca.provision-timeout; the rotation was refused rather than left waiting on an "
					+ "external service");
		}
	}

	public Mono<List<String>> trustedCaKeys(String kind) {
		return caConfigs.findByCaKind(kind).filter(c -> TRUSTED_STATES.contains(c.rotationState()))
				.concatMap(config -> caKeyMaterials.findByCaConfigId(config.id())
						.map(material -> localCaFactory.publicAuthorizedKey(config, material)))
				.collectList();
	}

	/**
	 * Runs the {@link CaKeyProvisioner} registered for {@code backend} — selected
	 * by backend id rather than branched on, so a key-service backend is a new
	 * implementation rather than a new case here — off the event loop and bounded
	 * by {@link #provisionTimeout}. Deliberately has <b>no transaction</b>:
	 * provisioning does real network I/O for a key-service backend (the one vault
	 * read at adoption) or CPU-bound keygen for local, but it writes nothing, so it
	 * has no atomicity need with anything else. Holding a database transaction open
	 * across a call to an external service would pin an R2DBC connection on that
	 * service's silence for no reason; a fixed boundedElastic pool is why the call
	 * is off the event loop rather than merely why it is not blocking. Callers
	 * persist the result themselves ({@link #persistIncoming}), inside whatever
	 * transaction they need.
	 */
	public Mono<CaKeyProvisioner.Provisioned> provisionIncoming(String kind, String newName, String backend,
			String keyReference, String algorithm) {
		return Mono
				.fromCallable(() -> provisionerFor(backend)
						.provision(new CaKeyProvisioner.Request(kind, newName, "incoming", keyReference, algorithm)))
				.subscribeOn(Schedulers.boundedElastic()).timeout(provisionTimeout)
				// The kind, not the key reference: nothing maps this exception, so it reaches
				// the framework's default handler and is logged there — and for a key service
				// the reference carries an account identifier. The kind is what an operator
				// needs to know which rotation stalled.
				.onErrorMap(TimeoutException.class, e -> new ProvisionTimedOut(backend, kind));
	}

	public Mono<CaConfig> persistIncoming(CaKeyProvisioner.Provisioned provisioned) {
		Mono<CaConfig> body = caConfigs.save(provisioned.config())
				.flatMap(saved -> caKeyMaterials.save(provisioned.material()).thenReturn(saved));
		return tx.transactional(body).single();
	}

	public Mono<CaConfig> beginRotation(String kind, String newName, String backend, String keyReference,
			String algorithm) {
		return provisionIncoming(kind, newName, backend, keyReference, algorithm).flatMap(this::persistIncoming);
	}

	private CaKeyProvisioner provisionerFor(String backend) {
		return provisioners.stream().filter(p -> backend.equals(p.backend())).findFirst()
				.orElseThrow(() -> new NoProvisionerForBackend(backend));
	}

	public Mono<Void> promote(String kind) {
		Mono<Void> body = demote(kind, "active", "outgoing").then(promoteFirst(kind, "incoming", "active"));
		return tx.transactional(body).then();
	}

	public Mono<Void> drain(String kind) {
		Mono<Void> body = caConfigs.findByCaKind(kind).filter(c -> "outgoing".equals(c.rotationState()))
				.concatMap(c -> caConfigs.save(withState(c, "expired"))).then();
		return tx.transactional(body).then();
	}

	private Mono<Void> demote(String kind, String from, String to) {
		return caConfigs.findByCaKindAndRotationState(kind, from).flatMap(c -> caConfigs.save(withState(c, to))).then();
	}

	private Mono<Void> promoteFirst(String kind, String from, String to) {
		return caConfigs.findByCaKind(kind).filter(c -> from.equals(c.rotationState())).next()
				.switchIfEmpty(Mono.error(new IllegalStateException("no " + from + " " + kind + " CA to promote")))
				.flatMap(c -> caConfigs.save(withState(c, to))).then();
	}

	private static CaConfig withState(CaConfig c, String state) {
		return new CaConfig(c.id(), c.name(), c.caKind(), c.backend(), c.keyReference(), c.algorithm(), state,
				c.origin(), c.version(), c.createdAt(), c.updatedAt());
	}
}
