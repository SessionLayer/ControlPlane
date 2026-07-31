package io.sessionlayer.controlplane.ca;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import io.sessionlayer.controlplane.ca.CaSignerService.NoSignerAvailable;
import io.sessionlayer.controlplane.ca.backend.azure.AzureKeyVaultSignerFactory;
import io.sessionlayer.controlplane.ca.backend.azure.KeyVaultSigner;
import io.sessionlayer.controlplane.data.config.CaConfig;
import io.sessionlayer.controlplane.data.config.CaConfigRepository;
import io.sessionlayer.controlplane.data.runtime.CaKeyMaterial;
import io.sessionlayer.controlplane.data.runtime.CaKeyMaterialRepository;
import io.sessionlayer.controlplane.observability.SloMetrics;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.ObjectProvider;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

/**
 * There is no code path from an {@code azure_keyvault} {@code ca_config} row to
 * {@link LocalCaFactory}: a CA the operator configured for Key Vault must never
 * fall back to signing from the database. Every azure_keyvault failure mode —
 * no factory bean, missing key material, a malformed key_reference — is
 * {@link NoSignerAvailable}, never local.
 */
class CaSignerServiceTest {

	private static KeyPair ecKeyPair() {
		try {
			KeyPairGenerator g = KeyPairGenerator.getInstance("EC");
			g.initialize(new ECGenParameterSpec("secp256r1"));
			return g.generateKeyPair();
		} catch (Exception e) {
			throw new IllegalStateException(e);
		}
	}

	/** A well-formed Key Vault version: 32 lowercase hex characters. */
	private static final String VERSION = "abcdef0123456789abcdef0123456789";

	private static CaConfig azureConfig(String keyReference) {
		return CaConfig.create("session-ca", "session", "azure_keyvault", keyReference, "ecdsa-p256", "active",
				"default");
	}

	private static CaKeyMaterial materialWithPublicKey(CaConfig config, ECPublicKey publicKey) {
		return CaKeyMaterial.create(config.id(), config.name(), "n/a", new byte[]{1}, new byte[12],
				publicKey.getEncoded(), "ecdsa-p256");
	}

	@SuppressWarnings("unchecked")
	private static ObjectProvider<AzureKeyVaultSignerFactory> noAzureFactory() {
		return mock(ObjectProvider.class);
	}

	@SuppressWarnings("unchecked")
	private static ObjectProvider<AzureKeyVaultSignerFactory> providerReturning(AzureKeyVaultSignerFactory factory) {
		ObjectProvider<AzureKeyVaultSignerFactory> provider = mock(ObjectProvider.class);
		when(provider.getIfAvailable()).thenReturn(factory);
		return provider;
	}

	private static CaSignerService service(CaConfigRepository configs, CaKeyMaterialRepository keys,
			LocalCaFactory localCaFactory, ObjectProvider<AzureKeyVaultSignerFactory> azureFactory) {
		return new CaSignerService(configs, keys, localCaFactory, new SloMetrics(new SimpleMeterRegistry()),
				azureFactory);
	}

	@Test
	void azureConfiguredCaWithNoAzureBeanFailsClosedAndNeverTouchesLocalCaFactoryOrKeyMaterial() {
		CaConfigRepository configs = mock(CaConfigRepository.class);
		CaKeyMaterialRepository keys = mock(CaKeyMaterialRepository.class);
		LocalCaFactory localCaFactory = mock(LocalCaFactory.class);
		CaConfig config = azureConfig("https://myvault.vault.azure.net/keys/ssh-ca/" + VERSION);

		CaSignerService service = service(configs, keys, localCaFactory, noAzureFactory());

		StepVerifier.create(service.signerFor(config)).expectErrorSatisfies(
				error -> assertThat(error).isInstanceOf(NoSignerAvailable.class).hasMessageContaining("Key Vault"))
				.verify();

		// Not just "no wrong signer" but no interaction at all: an azure_keyvault
		// row with no Key Vault support never even queries local key material, let
		// alone unwraps it.
		verifyNoInteractions(localCaFactory, keys);
	}

	@Test
	void azureConfiguredCaWithMissingKeyMaterialFailsClosed() {
		CaConfigRepository configs = mock(CaConfigRepository.class);
		CaKeyMaterialRepository keys = mock(CaKeyMaterialRepository.class);
		LocalCaFactory localCaFactory = mock(LocalCaFactory.class);
		AzureKeyVaultSignerFactory azureFactory = mock(AzureKeyVaultSignerFactory.class);
		when(azureFactory.vaultUri()).thenReturn("https://myvault.vault.azure.net");

		CaConfig config = azureConfig("https://myvault.vault.azure.net/keys/ssh-ca/" + VERSION);
		when(keys.findByCaConfigId(config.id())).thenReturn(Mono.empty());

		CaSignerService service = service(configs, keys, localCaFactory, providerReturning(azureFactory));

		StepVerifier.create(service.signerFor(config)).expectError(NoSignerAvailable.class).verify();
		verifyNoInteractions(localCaFactory);
	}

	@Test
	void azureConfiguredCaWithAVersionLessKeyReferenceFailsClosed() {
		CaConfigRepository configs = mock(CaConfigRepository.class);
		CaKeyMaterialRepository keys = mock(CaKeyMaterialRepository.class);
		LocalCaFactory localCaFactory = mock(LocalCaFactory.class);
		AzureKeyVaultSignerFactory azureFactory = mock(AzureKeyVaultSignerFactory.class);
		when(azureFactory.vaultUri()).thenReturn("https://myvault.vault.azure.net");

		// version-less is refused by KeyVaultKeyReference, before any vault call.
		CaConfig config = azureConfig("https://myvault.vault.azure.net/keys/ssh-ca");
		CaKeyMaterial material = materialWithPublicKey(config, (ECPublicKey) ecKeyPair().getPublic());
		when(keys.findByCaConfigId(config.id())).thenReturn(Mono.just(material));

		CaSignerService service = service(configs, keys, localCaFactory, providerReturning(azureFactory));

		StepVerifier.create(service.signerFor(config)).expectErrorSatisfies(
				error -> assertThat(error).isInstanceOf(NoSignerAvailable.class).hasMessageContaining("Key Vault"))
				.verify();
		verifyNoInteractions(localCaFactory);
	}

	@Test
	void azureConfiguredCaBuildsASignerWhenTheFactoryAndKeyMaterialAreBothPresent() {
		CaConfigRepository configs = mock(CaConfigRepository.class);
		CaKeyMaterialRepository keys = mock(CaKeyMaterialRepository.class);
		LocalCaFactory localCaFactory = mock(LocalCaFactory.class);
		AzureKeyVaultSignerFactory azureFactory = mock(AzureKeyVaultSignerFactory.class);
		when(azureFactory.vaultUri()).thenReturn("https://myvault.vault.azure.net");
		KeyVaultSigner signerDouble = mock(KeyVaultSigner.class);
		when(azureFactory.signerFor(any(), any())).thenReturn(signerDouble);

		ECPublicKey publicKey = (ECPublicKey) ecKeyPair().getPublic();
		when(signerDouble.publicKey()).thenReturn(publicKey);
		CaConfig config = azureConfig("https://myvault.vault.azure.net/keys/ssh-ca/" + VERSION);
		CaKeyMaterial material = materialWithPublicKey(config, publicKey);
		when(keys.findByCaConfigId(config.id())).thenReturn(Mono.just(material));

		CaSignerService service = service(configs, keys, localCaFactory, providerReturning(azureFactory));

		StepVerifier.create(service.signerFor(config)).assertNext(signer -> {
			assertThat(signer.keyType()).isEqualTo(CaKeyType.ECDSA_NISTP256);
			assertThat(signer.caPublicKeyBlob()).isNotEmpty();
		}).verifyComplete();
		verifyNoInteractions(localCaFactory);
	}

	@Test
	void localBackendDispatchIsUnaffected() {
		CaConfigRepository configs = mock(CaConfigRepository.class);
		CaKeyMaterialRepository keys = mock(CaKeyMaterialRepository.class);
		LocalCaFactory localCaFactory = mock(LocalCaFactory.class);
		SshCertSigner localSigner = mock(SshCertSigner.class);

		CaConfig config = CaConfig.create("session-ca", "session", "local", "local:id", "ecdsa-p256", "active",
				"default");
		CaKeyMaterial material = materialWithPublicKey(config, (ECPublicKey) ecKeyPair().getPublic());
		when(keys.findByCaConfigId(config.id())).thenReturn(Mono.just(material));
		when(localCaFactory.load(config, material)).thenReturn(localSigner);

		CaSignerService service = service(configs, keys, localCaFactory, noAzureFactory());

		StepVerifier.create(service.signerFor(config)).expectNext(localSigner).verifyComplete();
	}
}
