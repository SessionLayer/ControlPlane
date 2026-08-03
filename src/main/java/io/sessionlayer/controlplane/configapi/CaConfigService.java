package io.sessionlayer.controlplane.configapi;

import io.sessionlayer.controlplane.audit.AuditEventStore;
import io.sessionlayer.controlplane.ca.CaBackendCapabilities;
import io.sessionlayer.controlplane.ca.CaRotationService;
import io.sessionlayer.controlplane.ca.backend.aws.AwsKmsSignerFactory;
import io.sessionlayer.controlplane.ca.backend.aws.KmsKeyArn;
import io.sessionlayer.controlplane.ca.backend.azure.AzureKeyVaultSignerFactory;
import io.sessionlayer.controlplane.ca.backend.azure.KeyVaultKeyReference;
import io.sessionlayer.controlplane.data.config.CaConfig;
import io.sessionlayer.controlplane.data.config.CaConfigRepository;
import io.sessionlayer.controlplane.web.ApiProblemException;
import io.sessionlayer.controlplane.web.CursorPages;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.dao.OptimisticLockingFailureException;
import org.springframework.data.relational.core.query.Criteria;
import org.springframework.stereotype.Service;
import org.springframework.transaction.reactive.TransactionalOperator;
import reactor.core.publisher.Mono;

@Service
public class CaConfigService {

	private static final String ORIGIN_API = "api";
	private static final String ACTIVE = "active";
	private static final String AZURE_KEYVAULT = "azure_keyvault";
	private static final String AWS_KMS = "aws_kms";

	private static final Set<String> API_KINDS = Set.of("user", "session", "host");

	private final CaConfigRepository caConfigs;
	private final CaRotationService rotation;
	private final CursorPages cursorPages;
	private final AuditEventStore audit;
	private final TransactionalOperator tx;
	private final ObjectProvider<AzureKeyVaultSignerFactory> azureSignerFactory;
	private final ObjectProvider<AwsKmsSignerFactory> awsKmsSignerFactory;

	public CaConfigService(CaConfigRepository caConfigs, CaRotationService rotation, CursorPages cursorPages,
			AuditEventStore audit, TransactionalOperator tx,
			ObjectProvider<AzureKeyVaultSignerFactory> azureSignerFactory,
			ObjectProvider<AwsKmsSignerFactory> awsKmsSignerFactory) {
		this.caConfigs = caConfigs;
		this.rotation = rotation;
		this.cursorPages = cursorPages;
		this.audit = audit;
		this.tx = tx;
		this.azureSignerFactory = azureSignerFactory;
		this.awsKmsSignerFactory = awsKmsSignerFactory;
	}

	public Mono<CursorPages.Page<CaConfig>> list(String cursor, Integer limit) {
		return cursorPages.page(CaConfig.class, Criteria.where("caKind").in(API_KINDS), cursor, limit, CaConfig::id);
	}

	public Mono<CaConfig> get(UUID id) {
		return caConfigs.findById(id).filter(ca -> API_KINDS.contains(ca.caKind()))
				.switchIfEmpty(Mono.error(ApiProblemException.notFound("ca", id)));
	}

	/**
	 * Only ever a genuinely new CA kind: cold start provisions the three SSH kinds,
	 * so on any booted Control Plane this is otherwise a guaranteed conflict.
	 * Diagnosed ahead of the write so the 409 names the way out — rotating
	 * {@code backend} onto a different key service — instead of the generic
	 * unique-index message.
	 */
	public Mono<CaConfig> create(String actor, String name, String caKind, String backend, String keyReference,
			String algorithm) {
		validate(backend, keyReference, algorithm);
		return caConfigs.findByCaKindAndRotationState(caKind, ACTIVE).hasElement().flatMap(hasActive -> {
			if (hasActive) {
				return Mono.<CaConfig>error(ApiProblemException.conflict("the '" + caKind
						+ "' kind already has an active CA — POST /v1/cas/{caId}/rotate is how it moves onto a "
						+ "different backend, not another create"));
			}
			CaConfig ca = CaConfig.create(name, caKind, backend, keyReference, algorithm, ACTIVE, ORIGIN_API);
			return persist(null, ca, actor, "ca.create", name);
		});
	}

	/**
	 * {@code backend}/{@code keyReference}/{@code algorithm} describe the CA's
	 * <b>key</b>, and a key cannot be changed by editing a row: {@code update}
	 * bypasses {@link CaRotationService} entirely, so changing any of the three on
	 * an active CA would leave {@code ca_key_material} untouched while the
	 * persisted public key goes stale relative to the new reference — every
	 * certificate this CA kind issues would then fail to sign until someone
	 * rotates. Refused outright for an active CA — {@code UpdateCaRequest} carries
	 * only these three fields plus {@code version}, so there is nothing else a
	 * {@code PUT} on an active CA could legitimately change, and a {@code 200}
	 * would claim it did something it did not.
	 *
	 * <p>
	 * Refused even when the submitted values are byte-identical to what is already
	 * stored: this is not "reject a change", it is "this operation has nothing it
	 * is allowed to do to an active CA", and a client cannot tell which case it is
	 * in without a prior read anyway. {@code POST /v1/cas/{caId}/rotate} is the
	 * only operation that provisions a real key and re-publishes trust, so it is
	 * the only one allowed to touch them. Non-active rows
	 * (incoming/outgoing/expired) are not signing and remain editable.
	 */
	public Mono<CaConfig> update(UUID id, String actor, Long expectedVersion, String backend, String keyReference,
			String algorithm) {
		return get(id).flatMap(existing -> {
			requireVersion(expectedVersion, existing.version());
			if (ACTIVE.equals(existing.rotationState())) {
				return Mono.<CaConfig>error(ApiProblemException.conflict(
						"the active CA's backend/keyReference/algorithm describe its key and cannot be changed by "
								+ "update — POST /v1/cas/{caId}/rotate is how a CA's key changes"));
			}
			validate(backend, keyReference, algorithm);
			CaConfig updated = new CaConfig(existing.id(), existing.name(), existing.caKind(), backend, keyReference,
					algorithm, existing.rotationState(), ORIGIN_API, existing.version(), existing.createdAt(),
					existing.updatedAt());
			return persist(existing, updated, actor, "ca.update", existing.name());
		});
	}

	public Mono<Void> delete(UUID id, String actor) {
		return caConfigs.findById(id).flatMap(existing -> {
			if (!API_KINDS.contains(existing.caKind())) {
				return Mono.<Void>error(ApiProblemException.notFound("ca", id));
			}
			if (ACTIVE.equals(existing.rotationState())) {
				return Mono.<Void>error(ApiProblemException
						.conflict("cannot delete the active CA of kind '" + existing.caKind() + "' — rotate first"));
			}
			return deleteAndAudit(id, actor, existing);
		}).switchIfEmpty(Mono.defer(() -> deleteAndAudit(id, actor, null)));
	}

	/**
	 * Rotate the CA <b>kind</b> of {@code id} through the local rotation state
	 * machine (FR-CA-7): provision a fresh incoming CA, promote it to active and
	 * demote the current active to outgoing (both trusted during the overlap), then
	 * return the new active CA. Never returns private material.
	 *
	 * <p>
	 * {@code backend}/{@code keyReference}/{@code algorithm} are optional overrides
	 * for the incoming key (contract {@code RotateCaRequest}); an omitted one
	 * inherits the current active CA's value. Overriding {@code backend} is the
	 * adoption path onto a different key service — validated through the same
	 * capability/private-material gate as create/update, before anything is
	 * written.
	 */
	public Mono<CaConfig> rotate(UUID id, String actor, String backend, String keyReference, String algorithm) {
		return get(id).flatMap(existing -> {
			String kind = existing.caKind();
			String resolvedBackend = backend != null ? backend : existing.backend();
			String resolvedAlgorithm = algorithm != null ? algorithm : existing.algorithm();
			String resolvedKeyReference = keyReference != null ? keyReference : existing.keyReference();
			validate(resolvedBackend, resolvedKeyReference, resolvedAlgorithm);
			// Resolved BEFORE the transaction opens: provisioning does real network I/O
			// for a key-service backend and writes nothing, so it has no atomicity need
			// with the audit record below, and no R2DBC connection sits open across a
			// call to an external service.
			return rotation
					.provisionIncoming(kind, kind + "-" + UUID.randomUUID(), resolvedBackend, resolvedKeyReference,
							resolvedAlgorithm)
					.onErrorMap(CaRotationService.NoProvisionerForBackend.class,
							e -> ApiProblemException.conflict(e.getMessage()))
					.flatMap(provisioned -> {
						// Atomic: persisting the new key, promoting it, and the audit commit
						// happen in one transaction (the inner CaRotationService tx joins this
						// outer one, REQUIRED), so a signing-key rotation can never stand
						// without its audit record.
						Mono<CaConfig> rotated = rotation
								.persistIncoming(provisioned).then(rotation.promote(kind)).then(
										caConfigs.findByCaKindAndRotationState(kind, ACTIVE))
								.flatMap(active -> audit.recordChange(actor, active.id().toString(), "ca.rotate",
										Map.of("kind", kind), existing, active).thenReturn(active));
						return tx.transactional(rotated).onErrorMap(DataIntegrityViolationException.class,
								e -> ApiProblemException
										.conflict("a concurrent rotation of the '" + kind + "' CA is in progress"));
					});
		});
	}

	private Mono<Void> deleteAndAudit(UUID id, String actor, CaConfig before) {
		return tx.transactional(caConfigs.deleteById(id)
				.then(audit.recordChange(actor, id.toString(), "ca.delete", Map.of(), before, null)));
	}

	private Mono<CaConfig> persist(CaConfig before, CaConfig ca, String actor, String action, String name) {
		Mono<CaConfig> body = caConfigs.save(ca)
				.flatMap(saved -> audit
						.recordChange(actor, saved.id().toString(), action, Map.of("name", name), before, saved)
						.thenReturn(saved));
		return tx.transactional(body)
				.onErrorMap(OptimisticLockingFailureException.class,
						e -> ApiProblemException.conflict("the CA was modified concurrently (stale version)"))
				.onErrorMap(DataIntegrityViolationException.class, e -> ApiProblemException
						.conflict("a CA named '" + name + "' already exists, or its kind already has an active CA"));
	}

	private void validate(String backend, String keyReference, String algorithm) {
		if (keyReference == null || keyReference.contains("PRIVATE KEY") || keyReference.contains("BEGIN ")) {
			throw ApiProblemException.validation("keyReference must be a backend key reference, not private material");
		}
		// The ca_config CHECK, and the contract enum that mirrors it, are deliberately
		// wider than what any backend can actually sign: both are widened and never
		// narrowed, so a row an upgraded deployment already holds stays readable. This
		// is the stricter gate that stops a NEW one being written, and it asks the same
		// capability table the signer asks (Design D6 lives there, per backend). A rule
		// restated here would be a second list, free to drift from the one enforced.
		try {
			CaBackendCapabilities.validate(backend, algorithm);
		} catch (RuntimeException unsupported) {
			throw ApiProblemException.validation(unsupported.getMessage());
		}
		if (AZURE_KEYVAULT.equals(backend)) {
			validateAzureKeyReference(keyReference);
		}
		if (AWS_KMS.equals(backend)) {
			validateAwsKmsKeyReference(keyReference);
		}
	}

	/**
	 * The mandatory pinned key version and the configured-vault allow-list must
	 * hold at the write path, not only when a signer is loaded to sign — a
	 * version-less or wrong-vault reference stored here would otherwise be caught
	 * only the first time this CA tries to sign, far too late.
	 */
	private void validateAzureKeyReference(String keyReference) {
		AzureKeyVaultSignerFactory factory = azureSignerFactory.getIfAvailable();
		if (factory == null) {
			throw ApiProblemException.validation(
					"azure_keyvault is not configured on this Control Plane (sessionlayer.ca.azure.enabled)");
		}
		try {
			KeyVaultKeyReference.parse(keyReference, factory.vaultUri());
		} catch (KeyVaultKeyReference.InvalidKeyReference invalid) {
			throw ApiProblemException.validation(invalid.getMessage());
		}
	}

	/**
	 * The alias refusal and the configured-account allow-list must hold at the
	 * write path, not only when a signer is loaded to sign — an alias or a
	 * foreign-account ARN stored here would otherwise be caught only the first time
	 * this CA tries to sign, far too late.
	 */
	private void validateAwsKmsKeyReference(String keyReference) {
		AwsKmsSignerFactory factory = awsKmsSignerFactory.getIfAvailable();
		if (factory == null) {
			throw ApiProblemException
					.validation("aws_kms is not configured on this Control Plane (sessionlayer.ca.aws.enabled)");
		}
		try {
			KmsKeyArn.parse(keyReference, factory.anchor());
		} catch (KmsKeyArn.InvalidKeyReference invalid) {
			throw ApiProblemException.validation(invalid.getMessage());
		}
	}

	private static void requireVersion(Long expected, Long actual) {
		if (expected != null && !expected.equals(actual)) {
			throw ApiProblemException.conflict("stale version " + expected + " (current " + actual + ")");
		}
	}
}
