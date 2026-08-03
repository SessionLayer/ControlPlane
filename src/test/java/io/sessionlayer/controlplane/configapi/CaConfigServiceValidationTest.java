package io.sessionlayer.controlplane.configapi;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.catchThrowableOfType;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import io.sessionlayer.controlplane.audit.AuditEventStore;
import io.sessionlayer.controlplane.ca.CaKeyProvisioner;
import io.sessionlayer.controlplane.ca.CaRotationService;
import io.sessionlayer.controlplane.ca.backend.aws.AwsKmsSignerFactory;
import io.sessionlayer.controlplane.ca.backend.aws.KmsKeyArn;
import io.sessionlayer.controlplane.ca.backend.azure.AzureKeyVaultSignerFactory;
import io.sessionlayer.controlplane.data.config.CaConfig;
import io.sessionlayer.controlplane.data.config.CaConfigRepository;
import io.sessionlayer.controlplane.data.runtime.CaKeyMaterial;
import io.sessionlayer.controlplane.web.ApiProblemException;
import io.sessionlayer.controlplane.web.ApiProblemType;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.ArgumentMatchers;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.transaction.reactive.TransactionalOperator;
import reactor.core.publisher.Mono;

/**
 * The {@code ca_config.algorithm} CHECK, and the contract enum mirroring it,
 * admit backend/algorithm pairs no signer can produce; the service is the
 * stricter gate that refuses to store a new one. Without it such a pair is
 * accepted, persisted, and then throws in the signer as a 500 long after the
 * write. Both axes matter: the algorithm (ed25519, RSA) and the curve (a cloud
 * backend signs P-256 only).
 *
 * <p>
 * The refusal cases build the service with <b>null</b> collaborators on
 * purpose: a rejection that arrived even one step later would dereference a
 * null repository, so "nothing is written" is proven by construction rather
 * than asserted.
 */
class CaConfigServiceValidationTest {

	private static final String ACTOR = "operator";
	private static final String KEY_REFERENCE = "local:handle";
	/** A real Key Vault version shape (32 lowercase hex characters). */
	private static final String AZURE_KEY_VERSION = "0123456789abcdef0123456789abcdef";

	private static CaConfigService withNoCollaborators() {
		return new CaConfigService(null, null, null, null, null, null, null);
	}

	/**
	 * An {@code ObjectProvider} whose only registered bean is a mock
	 * {@code AzureKeyVaultSignerFactory} pinned to {@code vaultUri} — enough for
	 * {@code KeyVaultKeyReference.parse} to run against a real allow-list anchor
	 * without a live vault.
	 */
	private static ObjectProvider<AzureKeyVaultSignerFactory> azureConfiguredFor(String vaultUri) {
		AzureKeyVaultSignerFactory factory = mock(AzureKeyVaultSignerFactory.class);
		when(factory.vaultUri()).thenReturn(vaultUri);
		@SuppressWarnings("unchecked")
		ObjectProvider<AzureKeyVaultSignerFactory> provider = mock(ObjectProvider.class);
		when(provider.getIfAvailable()).thenReturn(factory);
		return provider;
	}

	/** No {@code AzureKeyVaultSignerFactory} bean at all — Azure not configured. */
	private static ObjectProvider<AzureKeyVaultSignerFactory> azureNotConfigured() {
		@SuppressWarnings("unchecked")
		ObjectProvider<AzureKeyVaultSignerFactory> provider = mock(ObjectProvider.class);
		when(provider.getIfAvailable()).thenReturn(null);
		return provider;
	}

	/**
	 * The KMS counterpart: a mock factory pinned to one account/region/partition,
	 * enough for {@code KmsKeyArn.parse} to run against a real allow-list anchor
	 * without a live KMS.
	 */
	private static ObjectProvider<AwsKmsSignerFactory> awsKmsConfigured() {
		AwsKmsSignerFactory factory = mock(AwsKmsSignerFactory.class);
		when(factory.anchor()).thenReturn(new KmsKeyArn.Anchor("aws", "us-east-1", "111122223333"));
		@SuppressWarnings("unchecked")
		ObjectProvider<AwsKmsSignerFactory> provider = mock(ObjectProvider.class);
		when(provider.getIfAvailable()).thenReturn(factory);
		return provider;
	}

	private static ObjectProvider<AwsKmsSignerFactory> awsKmsNotConfigured() {
		@SuppressWarnings("unchecked")
		ObjectProvider<AwsKmsSignerFactory> provider = mock(ObjectProvider.class);
		when(provider.getIfAvailable()).thenReturn(null);
		return provider;
	}

	@ParameterizedTest
	@ValueSource(strings = {"ed25519", "rsa-2048", "rsa-4096"})
	void anUnassemblableAlgorithmIsRefusedOnCreateBeforeAnythingIsWritten(String algorithm) {
		ApiProblemException problem = catchThrowableOfType(ApiProblemException.class, () -> withNoCollaborators()
				.create(ACTOR, "ca-" + algorithm, "user", "local", KEY_REFERENCE, algorithm));

		assertThat(problem).isNotNull();
		assertThat(problem.type()).isEqualTo(ApiProblemType.VALIDATION);
		assertThat(problem.type().status().value()).isEqualTo(422);
		assertThat(problem.getMessage()).contains(algorithm);
	}

	/**
	 * update()'s algorithm gate applies to non-active rows too — an active CA is
	 * refused for a different reason before this rule is even reached (see
	 * updateRefusesToChangeAnActiveCasAlgorithm below), so this is exercised on a
	 * non-active row, the only shape update() can still write.
	 */
	@ParameterizedTest
	@ValueSource(strings = {"ed25519", "rsa-2048", "rsa-4096"})
	void anUnassemblableAlgorithmIsRefusedOnUpdateToo(String algorithm) {
		UUID id = UUID.randomUUID();
		CaConfigRepository caConfigs = mock(CaConfigRepository.class);
		when(caConfigs.findById(id)).thenReturn(Mono.just(outgoingSessionCa(id)));

		ApiProblemException problem = catchThrowableOfType(ApiProblemException.class,
				() -> new CaConfigService(caConfigs, null, null, null, null, null, null)
						.update(id, ACTOR, 0L, "local", KEY_REFERENCE, algorithm).block());

		assertThat(problem).isNotNull();
		assertThat(problem.type()).isEqualTo(ApiProblemType.VALIDATION);
		assertThat(problem.getMessage()).contains(algorithm);
		verify(caConfigs, never()).save(any());
	}

	/**
	 * An algorithm outside the CHECK entirely never reaches Postgres either: a
	 * constraint violation would surface as a 409, not the documented 422.
	 */
	@Test
	void anUnknownAlgorithmIsRefusedRatherThanLeftToTheDatabaseCheck() {
		ApiProblemException problem = catchThrowableOfType(ApiProblemException.class,
				() -> withNoCollaborators().create(ACTOR, "ca-x", "user", "local", KEY_REFERENCE, "p-384"));

		assertThat(problem).isNotNull();
		assertThat(problem.type()).isEqualTo(ApiProblemType.VALIDATION);
	}

	@Test
	void aNullAlgorithmIsRefused() {
		ApiProblemException problem = catchThrowableOfType(ApiProblemException.class,
				() -> withNoCollaborators().create(ACTOR, "ca-null", "user", "local", KEY_REFERENCE, null));

		assertThat(problem).isNotNull();
		assertThat(problem.type()).isEqualTo(ApiProblemType.VALIDATION);
	}

	/**
	 * Asserted on {@code local}, because a key-service backend is now refused for
	 * having no signer before the algorithm is considered at all — so this rule can
	 * only be observed on the backend that does sign.
	 */
	@Test
	void theRefusalNamesTheBackendThatCannotProduceTheAlgorithm() {
		ApiProblemException problem = catchThrowableOfType(ApiProblemException.class,
				() -> withNoCollaborators().create(ACTOR, "ca-local-ed", "user", "local", KEY_REFERENCE, "ed25519"));

		assertThat(problem).isNotNull();
		assertThat(problem.getMessage()).contains("local").contains("ed25519");
	}

	/**
	 * The curve axis, which the algorithm axis alone leaves open: a cloud backend
	 * signs P-256 only, so a P-384/P-521 row on one is stored and then throws in
	 * the signer — the same store-then-500 the assemblability rule closes for
	 * ed25519 and RSA.
	 */
	/**
	 * {@code vault} has no signer in this build, so it is refused before the write,
	 * whatever the curve. {@code azure_keyvault} and {@code aws_kms} are
	 * deliberately NOT in this list: both are real signers, so their refusal cases
	 * (an unversioned/wrong-vault reference, an alias/foreign-account ARN) belong
	 * to those backends' own tests, not this "no signer at all" rule.
	 */
	@ParameterizedTest
	@ValueSource(strings = {"ecdsa-p256", "ecdsa-p384", "ecdsa-p521"})
	void aBackendWithNoSignerIsRefusedBeforeAnythingIsWritten(String curve) {
		ApiProblemException problem = catchThrowableOfType(ApiProblemException.class,
				() -> withNoCollaborators().create(ACTOR, "ca-vault-" + curve, "user", "vault", "handle:x", curve));

		assertThat(problem).as(curve).isNotNull();
		assertThat(problem.type()).isEqualTo(ApiProblemType.VALIDATION);
		assertThat(problem.type().status().value()).isEqualTo(422);
		assertThat(problem.getMessage()).contains("vault").contains("no signer in this build");
	}

	@Test
	void privateKeyMaterialIsStillRefusedAheadOfTheAlgorithmRule() {
		ApiProblemException problem = catchThrowableOfType(ApiProblemException.class, () -> withNoCollaborators()
				.create(ACTOR, "ca-pem", "user", "local", "-----BEGIN PRIVATE KEY-----", "ed25519"));

		assertThat(problem).isNotNull();
		assertThat(problem.getMessage()).contains("private material");
	}

	/** ecdsa-p521 among them: implemented, and reachable end to end at last. */
	@ParameterizedTest
	@ValueSource(strings = {"ecdsa-p256", "ecdsa-p384", "ecdsa-p521"})
	void everyCurveTheLocalBackendSignsIsAcceptedAndReachesTheWrite(String algorithm) {
		assertThat(accepts("local", algorithm).algorithm()).isEqualTo(algorithm);
	}

	/**
	 * Returns the persisted row, so a rule that silently skipped the write fails.
	 */
	private static CaConfig accepts(String backend, String algorithm) {
		CaConfigRepository caConfigs = mock(CaConfigRepository.class);
		AuditEventStore audit = mock(AuditEventStore.class);
		TransactionalOperator tx = mock(TransactionalOperator.class);
		when(caConfigs.findByCaKindAndRotationState(any(), any())).thenReturn(Mono.empty());
		when(caConfigs.save(any(CaConfig.class))).thenAnswer(call -> Mono.just(call.<CaConfig>getArgument(0)));
		when(audit.recordChange(any(), any(), any(), any(), any(), any())).thenReturn(Mono.empty());
		when(tx.transactional(ArgumentMatchers.<Mono<CaConfig>>any())).thenAnswer(call -> call.getArgument(0));

		CaConfig saved = new CaConfigService(caConfigs, null, null, audit, tx, null, null)
				.create(ACTOR, "ca-" + backend + "-" + algorithm, "user", backend, KEY_REFERENCE, algorithm).block();

		assertThat(saved).isNotNull();
		verify(caConfigs).save(any(CaConfig.class));
		return saved;
	}

	/**
	 * Cold start provisions the three SSH kinds, so on any booted Control Plane a
	 * second create for the same kind is a guaranteed conflict. The pre-commit
	 * check names the way out — rotate — instead of the generic unique-index
	 * message, and never reaches the write.
	 */
	@Test
	void createRefusesAnExistingActiveKindWithA409NamingRotate() {
		CaConfigRepository caConfigs = mock(CaConfigRepository.class);
		when(caConfigs.findByCaKindAndRotationState("user", "active")).thenReturn(Mono.just(existingActive("user")));

		ApiProblemException problem = catchThrowableOfType(ApiProblemException.class,
				() -> new CaConfigService(caConfigs, null, null, null, null, null, null)
						.create(ACTOR, "ca-dup", "user", "local", KEY_REFERENCE, "ecdsa-p256").block());

		assertThat(problem).isNotNull();
		assertThat(problem.type()).isEqualTo(ApiProblemType.CONFLICT);
		assertThat(problem.type().status().value()).isEqualTo(409);
		assertThat(problem.getMessage()).contains("/v1/cas/{caId}/rotate").contains("user");
		verify(caConfigs, never()).save(any());
	}

	/**
	 * Rotation is validated through the same capability gate as create/update,
	 * before {@link CaRotationService} is ever called — a rotation must not be able
	 * to leave a CA kind pointing at a key nothing can sign with.
	 */
	@Test
	void rotateRefusesABackendCaBackendCapabilitiesCannotSignBeforeAnythingIsWritten() {
		UUID id = UUID.randomUUID();
		CaConfigRepository caConfigs = mock(CaConfigRepository.class);
		CaRotationService rotation = mock(CaRotationService.class);
		when(caConfigs.findById(id)).thenReturn(Mono.just(activeSessionCa(id)));

		ApiProblemException problem = catchThrowableOfType(ApiProblemException.class,
				() -> new CaConfigService(caConfigs, rotation, null, null, null, null, null)
						.rotate(id, ACTOR, "vault", null, null).block());

		assertThat(problem).isNotNull();
		assertThat(problem.type()).isEqualTo(ApiProblemType.VALIDATION);
		assertThat(problem.type().status().value()).isEqualTo(422);
		assertThat(problem.getMessage()).contains("vault").contains("no signer in this build");
		verifyNoInteractions(rotation);
	}

	/**
	 * A backend {@code CaBackendCapabilities} says this build can sign, but with no
	 * {@link CaKeyProvisioner} wired for it, is an operator-actionable
	 * misconfiguration, not a server bug: a plain 500 would tell the operator
	 * nothing. Mapped to 409 naming the remedy (configure the backend) rather than
	 * reporting which properties are or are not set.
	 */
	@Test
	void rotateMapsNoProvisionerForBackendToA409NamingTheRemedy() {
		UUID id = UUID.randomUUID();
		CaConfigRepository caConfigs = mock(CaConfigRepository.class);
		CaRotationService rotation = mock(CaRotationService.class);
		when(caConfigs.findById(id)).thenReturn(Mono.just(activeSessionCa(id)));
		// provisionIncoming errors before persistIncoming/promote/audit are ever
		// reached (flatMap defers, unlike a `.then(...)` argument), so none of those
		// need stubbing here.
		when(rotation.provisionIncoming(eq("session"), any(), eq("azure_keyvault"), any(), eq("ecdsa-p256")))
				.thenReturn(Mono.error(new CaRotationService.NoProvisionerForBackend("azure_keyvault")));

		ApiProblemException problem = catchThrowableOfType(ApiProblemException.class,
				() -> new CaConfigService(caConfigs, rotation, null, null, null,
						azureConfiguredFor("https://sl.vault.azure.net"), null)
						.rotate(id, ACTOR, "azure_keyvault", "https://sl.vault.azure.net/keys/k/" + AZURE_KEY_VERSION,
								"ecdsa-p256")
						.block());

		assertThat(problem).isNotNull();
		assertThat(problem.type()).isEqualTo(ApiProblemType.CONFLICT);
		assertThat(problem.type().status().value()).isEqualTo(409);
		assertThat(problem.getMessage()).contains("azure_keyvault").contains("Configure the backend");
	}

	/**
	 * {@code RotateCaRequest}'s overrides are optional; an omitted one must inherit
	 * the active CA's current value rather than some other default — proven by
	 * asserting the exact arguments {@link CaRotationService} receives.
	 */
	@Test
	void rotateDefaultsOmittedOverridesToTheActiveCasCurrentValues() {
		UUID id = UUID.randomUUID();
		CaConfig existing = activeSessionCa(id);
		CaConfig incoming = new CaConfig(UUID.randomUUID(), "session-ca-2", "session", "local", "local:x", "ecdsa-p256",
				"incoming", "default", null, null, null);
		CaKeyProvisioner.Provisioned provisioned = provisioned(incoming);
		CaConfig promoted = new CaConfig(incoming.id(), "session-ca-2", "session", "local", "local:x", "ecdsa-p256",
				"active", "api", 0L, null, null);

		CaConfigRepository caConfigs = mock(CaConfigRepository.class);
		CaRotationService rotation = mock(CaRotationService.class);
		AuditEventStore audit = mock(AuditEventStore.class);
		TransactionalOperator tx = mock(TransactionalOperator.class);
		when(caConfigs.findById(id)).thenReturn(Mono.just(existing));
		when(rotation.provisionIncoming(eq("session"), any(), eq("local"), eq("local:x"), eq("ecdsa-p256")))
				.thenReturn(Mono.just(provisioned));
		when(rotation.persistIncoming(provisioned)).thenReturn(Mono.just(incoming));
		when(rotation.promote("session")).thenReturn(Mono.empty());
		when(caConfigs.findByCaKindAndRotationState("session", "active")).thenReturn(Mono.just(promoted));
		when(audit.recordChange(any(), any(), any(), any(), any(), any())).thenReturn(Mono.empty());
		when(tx.transactional(ArgumentMatchers.<Mono<CaConfig>>any())).thenAnswer(call -> call.getArgument(0));

		CaConfig result = new CaConfigService(caConfigs, rotation, null, audit, tx, null, null)
				.rotate(id, ACTOR, null, null, null).block();

		assertThat(result).isEqualTo(promoted);
		verify(rotation).provisionIncoming(eq("session"), any(), eq("local"), eq("local:x"), eq("ecdsa-p256"));
	}

	private static CaKeyProvisioner.Provisioned provisioned(CaConfig config) {
		CaKeyMaterial material = CaKeyMaterial.create(config.id(), config.name(), "kek:test", new byte[]{1},
				new byte[12], new byte[]{2}, "ecdsa-sha2-nistp256");
		return new CaKeyProvisioner.Provisioned(config, material);
	}

	/**
	 * An explicit {@code backend}/{@code keyReference} override in the request must
	 * reach {@link CaRotationService} exactly as given, not be silently dropped in
	 * favor of the active CA's own values — the adoption path (moving a CA onto a
	 * different key service) depends on the override actually being used.
	 */
	@Test
	void rotateHonorsExplicitBackendAndKeyReferenceOverridesRatherThanIgnoringThem() {
		UUID id = UUID.randomUUID();
		CaConfig existing = activeSessionCa(id);
		String newKeyReference = "https://sl.vault.azure.net/keys/session-key/" + AZURE_KEY_VERSION;
		CaConfig incoming = new CaConfig(UUID.randomUUID(), "session-ca-2", "session", "azure_keyvault",
				newKeyReference, "ecdsa-p256", "incoming", "default", null, null, null);
		CaKeyProvisioner.Provisioned provisioned = provisioned(incoming);
		CaConfig promoted = new CaConfig(incoming.id(), "session-ca-2", "session", "azure_keyvault", newKeyReference,
				"ecdsa-p256", "active", "api", 0L, null, null);

		CaConfigRepository caConfigs = mock(CaConfigRepository.class);
		CaRotationService rotation = mock(CaRotationService.class);
		AuditEventStore audit = mock(AuditEventStore.class);
		TransactionalOperator tx = mock(TransactionalOperator.class);
		when(caConfigs.findById(id)).thenReturn(Mono.just(existing));
		when(rotation.provisionIncoming(eq("session"), any(), eq("azure_keyvault"), eq(newKeyReference),
				eq("ecdsa-p256"))).thenReturn(Mono.just(provisioned));
		when(rotation.persistIncoming(provisioned)).thenReturn(Mono.just(incoming));
		when(rotation.promote("session")).thenReturn(Mono.empty());
		when(caConfigs.findByCaKindAndRotationState("session", "active")).thenReturn(Mono.just(promoted));
		when(audit.recordChange(any(), any(), any(), any(), any(), any())).thenReturn(Mono.empty());
		when(tx.transactional(ArgumentMatchers.<Mono<CaConfig>>any())).thenAnswer(call -> call.getArgument(0));

		CaConfig result = new CaConfigService(caConfigs, rotation, null, audit, tx,
				azureConfiguredFor("https://sl.vault.azure.net"), null)
				.rotate(id, ACTOR, "azure_keyvault", newKeyReference, "ecdsa-p256").block();

		assertThat(result.backend()).isEqualTo("azure_keyvault");
		assertThat(result.keyReference()).isEqualTo(newKeyReference);
		verify(rotation).provisionIncoming(eq("session"), any(), eq("azure_keyvault"), eq(newKeyReference),
				eq("ecdsa-p256"));
	}

	/**
	 * {@code update} bypasses {@link CaRotationService} entirely, so changing an
	 * active CA's backend/keyReference/algorithm through it leaves
	 * {@code ca_key_material} untouched — the persisted public key goes stale
	 * relative to the new key_reference, and every certificate this CA kind issues
	 * fails to sign until someone rotates. Those three fields describe the CA's
	 * key, and a key cannot be changed by editing a row: only rotation (which
	 * provisions/adopts a real key and re-publishes trust) may change them. The
	 * practical effect is that {@code PUT} on an active CA is a no-op, since those
	 * three are the only fields it can ever change — that is the correct shape, not
	 * an oversight.
	 */
	@Test
	void updateRefusesToChangeAnActiveCasBackend() {
		UUID id = UUID.randomUUID();
		CaConfigRepository caConfigs = mock(CaConfigRepository.class);
		when(caConfigs.findById(id)).thenReturn(Mono.just(activeSessionCa(id)));

		ApiProblemException problem = catchThrowableOfType(ApiProblemException.class,
				() -> new CaConfigService(caConfigs, null, null, null, null, null, null).update(id, ACTOR, 0L,
						"azure_keyvault", "https://sl.vault.azure.net/keys/k/" + AZURE_KEY_VERSION, "ecdsa-p256")
						.block());

		assertThat(problem).isNotNull();
		assertThat(problem.type()).isEqualTo(ApiProblemType.CONFLICT);
		assertThat(problem.type().status().value()).isEqualTo(409);
		assertThat(problem.getMessage()).contains("/v1/cas/{caId}/rotate");
		verify(caConfigs, never()).save(any());
	}

	/**
	 * Same refusal, isolated to keyReference alone changing (backend/algorithm
	 * unchanged).
	 */
	@Test
	void updateRefusesToChangeAnActiveCasKeyReference() {
		UUID id = UUID.randomUUID();
		CaConfigRepository caConfigs = mock(CaConfigRepository.class);
		when(caConfigs.findById(id)).thenReturn(Mono.just(activeSessionCa(id)));

		ApiProblemException problem = catchThrowableOfType(ApiProblemException.class,
				() -> new CaConfigService(caConfigs, null, null, null, null, null, null)
						.update(id, ACTOR, 0L, "local", "local:a-different-row", "ecdsa-p256").block());

		assertThat(problem).isNotNull();
		assertThat(problem.type()).isEqualTo(ApiProblemType.CONFLICT);
		assertThat(problem.type().status().value()).isEqualTo(409);
		assertThat(problem.getMessage()).contains("/v1/cas/{caId}/rotate");
		verify(caConfigs, never()).save(any());
	}

	/**
	 * Refuses even a byte-identical resubmission: the rule is "an active CA's key
	 * fields are not update()'s to touch", not "only a different value is refused"
	 * — a client cannot tell which case it is in without a prior read, and the
	 * correct move either way is rotate (or no call at all).
	 */
	@Test
	void updateRefusesAnActiveCaEvenWhenTheSubmittedValuesAlreadyMatch() {
		UUID id = UUID.randomUUID();
		CaConfig existing = activeSessionCa(id);
		CaConfigRepository caConfigs = mock(CaConfigRepository.class);
		when(caConfigs.findById(id)).thenReturn(Mono.just(existing));

		ApiProblemException problem = catchThrowableOfType(ApiProblemException.class,
				() -> new CaConfigService(caConfigs, null, null, null, null, null, null)
						.update(id, ACTOR, 0L, existing.backend(), existing.keyReference(), existing.algorithm())
						.block());

		assertThat(problem).isNotNull();
		assertThat(problem.type()).isEqualTo(ApiProblemType.CONFLICT);
		verify(caConfigs, never()).save(any());
	}

	/**
	 * Non-active rows (incoming/outgoing/expired) are not signing — still editable.
	 */
	@Test
	void updateStillEditsANonActiveCa() {
		UUID id = UUID.randomUUID();
		CaConfigRepository caConfigs = mock(CaConfigRepository.class);
		AuditEventStore audit = mock(AuditEventStore.class);
		TransactionalOperator tx = mock(TransactionalOperator.class);
		when(caConfigs.findById(id)).thenReturn(Mono.just(outgoingSessionCa(id)));
		when(caConfigs.save(any(CaConfig.class))).thenAnswer(call -> Mono.just(call.<CaConfig>getArgument(0)));
		when(audit.recordChange(any(), any(), any(), any(), any(), any())).thenReturn(Mono.empty());
		when(tx.transactional(ArgumentMatchers.<Mono<CaConfig>>any())).thenAnswer(call -> call.getArgument(0));

		CaConfig result = new CaConfigService(caConfigs, null, null, audit, tx, null, null)
				.update(id, ACTOR, 0L, "local", "local:rotated", "ecdsa-p384").block();

		assertThat(result.backend()).isEqualTo("local");
		assertThat(result.keyReference()).isEqualTo("local:rotated");
		assertThat(result.algorithm()).isEqualTo("ecdsa-p384");
		verify(caConfigs).save(any(CaConfig.class));
	}

	/**
	 * D-1: a Key Vault key_reference must be pinned to an exact version. A
	 * reference with no version segment at all is refused at the write path, not
	 * left to fail only when a signature is attempted.
	 */
	@Test
	void createRefusesAVersionLessAzureKeyReferenceAtTheWritePath() {
		ApiProblemException problem = catchThrowableOfType(ApiProblemException.class,
				() -> new CaConfigService(null, null, null, null, null,
						azureConfiguredFor("https://sl.vault.azure.net"), null).create(ACTOR, "ca-azkv-unpinned", "user",
								"azure_keyvault", "https://sl.vault.azure.net/keys/session-ca", "ecdsa-p256"));

		assertThat(problem).isNotNull();
		assertThat(problem.type()).isEqualTo(ApiProblemType.VALIDATION);
		assertThat(problem.type().status().value()).isEqualTo(422);
		assertThat(problem.getMessage()).contains("version");
	}

	/**
	 * D-3: the allow-list anchor. A key_reference naming any host but the
	 * configured vault is refused, so a compromised write path cannot redirect CA
	 * signing to a vault the operator did not configure.
	 */
	@Test
	void createRefusesAWrongVaultAzureKeyReferenceAtTheWritePath() {
		ApiProblemException problem = catchThrowableOfType(ApiProblemException.class,
				() -> new CaConfigService(null, null, null, null, null,
						azureConfiguredFor("https://sl.vault.azure.net"), null).create(ACTOR, "ca-azkv-wrongvault", "user",
								"azure_keyvault", "https://someone-elses-vault.vault.azure.net/keys/k/"
										+ "0123456789abcdef0123456789abcdef",
								"ecdsa-p256"));

		assertThat(problem).isNotNull();
		assertThat(problem.type()).isEqualTo(ApiProblemType.VALIDATION);
		assertThat(problem.type().status().value()).isEqualTo(422);
		assertThat(problem.getMessage()).contains("not the configured Key Vault");
	}

	/**
	 * A Control Plane with no Azure support configured has no
	 * {@code AzureKeyVaultSignerFactory} bean at all — refused rather than
	 * dereferencing a vault URI that does not exist.
	 */
	@Test
	void createRefusesAzureKeyvaultWhenNoVaultIsConfiguredOnThisControlPlane() {
		ApiProblemException problem = catchThrowableOfType(ApiProblemException.class,
				() -> new CaConfigService(null, null, null, null, null, azureNotConfigured(), null).create(ACTOR,
						"ca-azkv-unconfigured", "user", "azure_keyvault",
						"https://sl.vault.azure.net/keys/k/0123456789abcdef0123456789abcdef", "ecdsa-p256"));

		assertThat(problem).isNotNull();
		assertThat(problem.type()).isEqualTo(ApiProblemType.VALIDATION);
		assertThat(problem.getMessage()).contains("not configured");
	}

	/**
	 * The alias refusal is the pinning guarantee for KMS, and it has to hold at the
	 * write path: {@code kms:UpdateAlias} would otherwise repoint a live CA's
	 * signing key with nothing here ever seeing it change.
	 */
	@Test
	void createRefusesAnAliasKeyReferenceAtTheWritePath() {
		ApiProblemException problem = catchThrowableOfType(ApiProblemException.class,
				() -> new CaConfigService(null, null, null, null, null, null, awsKmsConfigured()).create(ACTOR,
						"ca-kms-alias", "user", "aws_kms", "arn:aws:kms:us-east-1:111122223333:alias/session-ca",
						"ecdsa-p256"));

		assertThat(problem).isNotNull();
		assertThat(problem.type()).isEqualTo(ApiProblemType.VALIDATION);
		assertThat(problem.type().status().value()).isEqualTo(422);
		assertThat(problem.getMessage()).contains("alias");
	}

	/**
	 * The allow-list anchor. A key ARN naming any account but the configured one is
	 * refused, so a compromised write path cannot redirect CA signing to a KMS key
	 * the operator does not own.
	 */
	@Test
	void createRefusesAForeignAccountKeyArnAtTheWritePath() {
		ApiProblemException problem = catchThrowableOfType(ApiProblemException.class,
				() -> new CaConfigService(null, null, null, null, null, null, awsKmsConfigured()).create(ACTOR,
						"ca-kms-wrongaccount", "user", "aws_kms",
						"arn:aws:kms:us-east-1:999988887777:key/1234abcd-12ab-34cd-56ef-1234567890ab", "ecdsa-p256"));

		assertThat(problem).isNotNull();
		assertThat(problem.type()).isEqualTo(ApiProblemType.VALIDATION);
		assertThat(problem.type().status().value()).isEqualTo(422);
		assertThat(problem.getMessage()).contains("only the configured account, region and partition are permitted");
	}

	/**
	 * A Control Plane with no KMS support configured has no
	 * {@code AwsKmsSignerFactory} bean at all — refused rather than dereferencing
	 * an anchor that does not exist.
	 */
	@Test
	void createRefusesAwsKmsWhenNoKmsIsConfiguredOnThisControlPlane() {
		ApiProblemException problem = catchThrowableOfType(ApiProblemException.class,
				() -> new CaConfigService(null, null, null, null, null, null, awsKmsNotConfigured()).create(ACTOR,
						"ca-kms-unconfigured", "user", "aws_kms",
						"arn:aws:kms:us-east-1:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab", "ecdsa-p256"));

		assertThat(problem).isNotNull();
		assertThat(problem.type()).isEqualTo(ApiProblemType.VALIDATION);
		assertThat(problem.getMessage()).contains("not configured");
	}

	private static CaConfig activeSessionCa(UUID id) {
		return new CaConfig(id, "session-ca", "session", "local", "local:x", "ecdsa-p256", "active", "api", 0L, null,
				null);
	}

	private static CaConfig outgoingSessionCa(UUID id) {
		return new CaConfig(id, "session-ca-old", "session", "local", "local:x", "ecdsa-p256", "outgoing", "api", 0L,
				null, null);
	}

	private static CaConfig existingActive(String kind) {
		return new CaConfig(UUID.randomUUID(), "ca-" + kind, kind, "local", "local:existing", "ecdsa-p256", "active",
				"api", 0L, null, null);
	}
}
