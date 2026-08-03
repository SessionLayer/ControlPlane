package io.sessionlayer.controlplane.ca;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.catchThrowableOfType;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import io.sessionlayer.controlplane.data.Uuids;
import io.sessionlayer.controlplane.data.config.CaConfig;
import io.sessionlayer.controlplane.data.config.CaConfigRepository;
import io.sessionlayer.controlplane.data.runtime.CaKeyMaterial;
import io.sessionlayer.controlplane.data.runtime.CaKeyMaterialRepository;
import java.time.Duration;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentMatchers;
import org.springframework.transaction.reactive.TransactionalOperator;
import reactor.core.publisher.Mono;

/**
 * {@code CaRotationService.beginRotation} dispatches to the
 * {@link CaKeyProvisioner} registered for the requested backend instead of
 * branching on the backend string. A second, non-local implementation
 * ({@link #fakeProvisioner}) proves that dispatch is real polymorphism rather
 * than a disguised {@code if (local)}; a backend with no registered provisioner
 * proves the fail-closed path writes nothing — rotation refuses rather than
 * provisioning anywhere else.
 */
class CaRotationServiceProvisionerTest {

	private static final String KIND = "session";

	private static CaRotationService serviceWith(List<CaKeyProvisioner> provisioners, CaConfigRepository caConfigs,
			CaKeyMaterialRepository caKeyMaterials) {
		return serviceWith(provisioners, caConfigs, caKeyMaterials, Duration.ofSeconds(10));
	}

	private static CaRotationService serviceWith(List<CaKeyProvisioner> provisioners, CaConfigRepository caConfigs,
			CaKeyMaterialRepository caKeyMaterials, Duration provisionTimeout) {
		LocalCaFactory localCaFactory = mock(LocalCaFactory.class);
		TransactionalOperator tx = mock(TransactionalOperator.class);
		when(tx.transactional(ArgumentMatchers.<Mono<CaConfig>>any())).thenAnswer(call -> call.getArgument(0));
		return new CaRotationService(caConfigs, caKeyMaterials, localCaFactory, provisioners, tx, provisionTimeout);
	}

	@Test
	void beginRotationDispatchesToTheProvisionerRegisteredForTheRequestedBackend() {
		CaConfigRepository caConfigs = mock(CaConfigRepository.class);
		CaKeyMaterialRepository caKeyMaterials = mock(CaKeyMaterialRepository.class);
		when(caConfigs.save(any(CaConfig.class))).thenAnswer(call -> Mono.just(call.<CaConfig>getArgument(0)));
		when(caKeyMaterials.save(any(CaKeyMaterial.class)))
				.thenAnswer(call -> Mono.just(call.<CaKeyMaterial>getArgument(0)));
		CaRotationService service = serviceWith(List.of(fakeProvisioner("fake-backend")), caConfigs, caKeyMaterials);

		CaConfig result = service.beginRotation(KIND, "session-fake", "fake-backend", "fake:handle", "ecdsa-p256")
				.block();

		assertThat(result).isNotNull();
		assertThat(result.backend()).isEqualTo("fake-backend");
		assertThat(result.caKind()).isEqualTo(KIND);
		verify(caConfigs).save(any(CaConfig.class));
		verify(caKeyMaterials).save(any(CaKeyMaterial.class));
	}

	@Test
	void beginRotationFailsClosedWithNoProvisionerAndWritesNothing() {
		CaConfigRepository caConfigs = mock(CaConfigRepository.class);
		CaKeyMaterialRepository caKeyMaterials = mock(CaKeyMaterialRepository.class);
		// A registered provisioner exists (for a DIFFERENT backend), so this proves
		// the lookup is by backend id, not merely "the list is empty".
		CaRotationService service = serviceWith(List.of(fakeProvisioner("fake-backend")), caConfigs, caKeyMaterials);

		CaRotationService.NoProvisionerForBackend error = catchThrowableOfType(
				CaRotationService.NoProvisionerForBackend.class,
				() -> service.beginRotation(KIND, "session-x", "azure_keyvault", "kv:handle", "ecdsa-p256").block());

		assertThat(error).isNotNull();
		assertThat(error.getMessage()).contains("azure_keyvault");
		verify(caConfigs, never()).save(any());
		verify(caKeyMaterials, never()).save(any());
	}

	/**
	 * A provisioner that never returns must not pin the rotation indefinitely: it
	 * has to fail within the configured bound, and — since
	 * {@code provisionIncoming} has no transaction to roll back — writing nothing
	 * is proven directly rather than inferred from a rollback.
	 */
	@Test
	void provisionIncomingTimesOutAndWritesNothingWhenAProvisionerNeverReturns() {
		CaConfigRepository caConfigs = mock(CaConfigRepository.class);
		CaKeyMaterialRepository caKeyMaterials = mock(CaKeyMaterialRepository.class);
		CaRotationService service = serviceWith(List.of(neverReturningProvisioner("slow-backend")), caConfigs,
				caKeyMaterials, Duration.ofMillis(200));

		CaRotationService.ProvisionTimedOut error = catchThrowableOfType(CaRotationService.ProvisionTimedOut.class,
				() -> service.provisionIncoming(KIND, "session-slow", "slow-backend", "slow:handle", "ecdsa-p256")
						.block());

		assertThat(error).isNotNull();
		// The kind and the backend, never the key reference. Nothing maps this
		// exception, so it reaches the framework's default handler and is logged
		// there — and a key service's reference carries an account identifier.
		assertThat(error.getMessage()).contains("slow-backend").contains(KIND).doesNotContain("slow:handle");
		verifyNoInteractions(caConfigs, caKeyMaterials);
	}

	private static CaKeyProvisioner neverReturningProvisioner(String backend) {
		return new CaKeyProvisioner() {
			@Override
			public String backend() {
				return backend;
			}

			@Override
			public Provisioned provision(Request request) {
				try {
					// Long enough to outlast the test's own timeout many times over; the
					// thread is abandoned (Reactor's timeout() cancels downstream, not the
					// blocking call itself), not interrupted, so it must not sleep forever.
					Thread.sleep(java.time.Duration.ofSeconds(30).toMillis());
				} catch (InterruptedException e) {
					Thread.currentThread().interrupt();
				}
				throw new IllegalStateException("unreachable: provisionIncoming must time out first");
			}
		};
	}

	private static CaKeyProvisioner fakeProvisioner(String backend) {
		return new CaKeyProvisioner() {
			@Override
			public String backend() {
				return backend;
			}

			@Override
			public Provisioned provision(Request request) {
				UUID configId = Uuids.v7();
				CaConfig config = new CaConfig(configId, request.caName(), request.caKind(), backend,
						request.keyReference(), request.algorithm(), request.rotationState(), "default", null, null,
						null);
				CaKeyMaterial material = CaKeyMaterial.createExternal(configId, request.caName(),
						"fake-public-key".getBytes(java.nio.charset.StandardCharsets.UTF_8), "ecdsa-sha2-nistp256",
						null);
				return new Provisioned(config, material);
			}
		};
	}
}
