package io.sessionlayer.controlplane.ca;

import io.sessionlayer.controlplane.ca.mtls.InternalMtlsCaService;
import io.sessionlayer.controlplane.data.config.CaConfigRepository;
import io.sessionlayer.controlplane.data.config.OperatorSettings;
import io.sessionlayer.controlplane.data.config.OperatorSettingsRepository;
import io.sessionlayer.controlplane.data.runtime.CaKeyMaterialRepository;
import java.util.List;
import org.springframework.r2dbc.core.DatabaseClient;
import org.springframework.stereotype.Service;
import org.springframework.transaction.reactive.TransactionalOperator;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

/**
 * Cold-start CA provisioning. On first run against an
 * empty DB it ensures the operator-settings singleton exists and provisions the
 * three CAs (user / internal session / host) exactly once, then is a no-op on
 * every subsequent start (idempotent, restart-safe). It is <b>race-safe</b>:
 * the whole operation runs under a Postgres transaction-scoped <b>advisory
 * lock</b>, so two starting instances cannot double-generate, and the
 * partial-unique active-per-kind index is a hard backstop.
 *
 * <p>
 * Local CAs are generated and KEK-wrapped with a loud production
 * warning; cloud CAs (KMS/KeyVault/Vault) are <b>referenced</b> via an
 * operator-pre-created {@code ca_config} (their key lives in the cloud, not
 * generated here).
 */
@Service
public class CaProvisioningService {

	private static final long COLD_START_LOCK = 0x53_4C_5F_43_41_5F_43_53L; // "SL_CA_CS"

	private static final List<String> CA_KINDS = List.of("session", "user", "host");

	private final OperatorSettingsRepository operatorSettings;
	private final CaConfigRepository caConfigs;
	private final CaKeyMaterialRepository caKeyMaterials;
	private final DatabaseClient db;
	private final TransactionalOperator tx;
	private final LocalCaFactory localCaFactory;
	private final InternalMtlsCaService internalMtlsCa;

	public CaProvisioningService(OperatorSettingsRepository operatorSettings, CaConfigRepository caConfigs,
			CaKeyMaterialRepository caKeyMaterials, DatabaseClient db, TransactionalOperator tx,
			LocalCaFactory localCaFactory, InternalMtlsCaService internalMtlsCa) {
		this.operatorSettings = operatorSettings;
		this.caConfigs = caConfigs;
		this.caKeyMaterials = caKeyMaterials;
		this.db = db;
		this.tx = tx;
		this.localCaFactory = localCaFactory;
		this.internalMtlsCa = internalMtlsCa;
	}

	public Mono<Void> provisionAll() {
		return alreadyProvisioned().flatMap(done -> done ? Mono.<Void>empty() : provisionUnderLock());
	}

	private Mono<Boolean> alreadyProvisioned() {
		return operatorSettings.findSingleton().hasElement().flatMap(hasSettings -> {
			if (!hasSettings) {
				return Mono.just(false);
			}
			return Flux.fromIterable(CA_KINDS)
					.concatMap(kind -> caConfigs.findByCaKindAndRotationState(kind, "active").hasElement())
					.all(present -> present)
					.flatMap(sshComplete -> sshComplete
							? caConfigs.findByCaKindAndRotationState("mtls", "active").hasElement()
							: Mono.just(false));
		});
	}

	private Mono<Void> provisionUnderLock() {
		Mono<Void> body = acquireLock().then(ensureSettings())
				.flatMap(settings -> Flux.fromIterable(CA_KINDS)
						.concatMap(kind -> ensureCa(kind, settings.defaultCaBackend())).then()
						// Provisioned inside the SAME lock + tx, so a cold boot brings up every CA
						// atomically.
						.then(internalMtlsCa.ensureProvisioned(settings.defaultCaBackend())));
		return tx.transactional(body).then();
	}

	private Mono<Long> acquireLock() {
		// lock_timeout: a wedged peer makes the advisory-lock wait FAIL rather than
		// block
		// the boot forever (LOCAL = this transaction only).
		return db.sql("SET LOCAL lock_timeout = '15s'").fetch().rowsUpdated()
				.then(db.sql("SELECT pg_advisory_xact_lock(:k)").bind("k", COLD_START_LOCK).fetch().rowsUpdated());
	}

	private Mono<OperatorSettings> ensureSettings() {
		return operatorSettings.findSingleton()
				.switchIfEmpty(Mono.defer(() -> operatorSettings.save(OperatorSettings.defaults())));
	}

	private Mono<Void> ensureCa(String kind, String backend) {
		return caConfigs.findByCaKindAndRotationState(kind, "active").hasElement()
				.flatMap(exists -> exists ? Mono.<Void>empty() : provisionKind(kind, backend));
	}

	private Mono<Void> provisionKind(String kind, String backend) {
		CaBackendCapabilities.validate(backend, CaKeyType.ECDSA_NISTP256.algorithmId());
		if (!"local".equals(backend)) {
			return Mono.error(new IllegalStateException("cold start cannot auto-generate a '" + backend + "' CA for '"
					+ kind + "': create the ca_config referencing the externally-managed key (key_reference)"));
		}
		return Mono.fromCallable(
				() -> localCaFactory.create(kind, kind + "-ca", "active", CaKeyType.ECDSA_NISTP256.algorithmId()))
				.flatMap(provisioned -> caConfigs.save(provisioned.config())
						.then(caKeyMaterials.save(provisioned.material())).then());
	}
}
