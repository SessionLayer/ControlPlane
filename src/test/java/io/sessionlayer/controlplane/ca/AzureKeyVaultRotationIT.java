package io.sessionlayer.controlplane.ca;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import io.sessionlayer.controlplane.ca.backend.azure.AzureKeyVaultCaProvisioner;
import io.sessionlayer.controlplane.ca.backend.azure.AzureKeyVaultSignerFactory;
import io.sessionlayer.controlplane.configapi.CaConfigService;
import io.sessionlayer.controlplane.data.config.CaConfig;
import io.sessionlayer.controlplane.data.config.CaConfigRepository;
import io.sessionlayer.controlplane.data.runtime.CaKeyMaterial;
import io.sessionlayer.controlplane.data.runtime.CaKeyMaterialRepository;
import io.sessionlayer.controlplane.support.AbstractAuthIT;
import io.sessionlayer.controlplane.web.ApiProblemException;
import java.security.KeyPairGenerator;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.util.UUID;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;

class AzureKeyVaultRotationIT extends AbstractAuthIT {

	private static final String VAULT_URI = "https://myvault.vault.azure.net";
	private static final String ACTOR = "svc-azkv-it";

	/** A well-formed Key Vault version: 32 lowercase hex characters. */
	private static final String VERSION = "abcdef0123456789abcdef0123456789";

	@TestConfiguration
	static class Doubles {
		@Bean
		@Primary
		AzureKeyVaultSignerFactory azureKeyVaultSignerFactory() {
			return mock(AzureKeyVaultSignerFactory.class);
		}

		@Bean
		@Primary
		AzureKeyVaultCaProvisioner azureKeyVaultCaProvisioner(AzureKeyVaultSignerFactory factory) {
			return new AzureKeyVaultCaProvisioner(factory);
		}
	}

	@Autowired
	private AzureKeyVaultSignerFactory azureFactory;
	@Autowired
	private CaConfigService caConfigService;
	@Autowired
	private CaConfigRepository caConfigs;
	@Autowired
	private CaKeyMaterialRepository caKeyMaterials;

	@AfterEach
	void resetCas() {
		// runtime.ca_key_material has NO FK to config.ca_config (a snapshot ref
		// across the runtime/config boundary), so its rows do not cascade - they are
		// left behind and each test seeds its own ids.
		caConfigs.deleteAll().block();
		Mockito.reset(azureFactory);
	}

	private static ECPublicKey ecPublicKey() {
		try {
			KeyPairGenerator g = KeyPairGenerator.getInstance("EC");
			g.initialize(new ECGenParameterSpec("secp256r1"));
			return (ECPublicKey) g.generateKeyPair().getPublic();
		} catch (Exception e) {
			throw new IllegalStateException(e);
		}
	}

	private UUID seedActiveLocalCa() {
		CaConfig created = caConfigService.create(ACTOR, "ca-" + UUID.randomUUID(), "session", "local",
				"local:seed-" + UUID.randomUUID(), "ecdsa-p256").block();
		return created.id();
	}

	@Test
	void rotatingOntoAzureKeyVaultWithAValidVersionedReferenceWritesAnExternalRow() {
		ECPublicKey publicKey = ecPublicKey();
		when(azureFactory.vaultUri()).thenReturn(VAULT_URI);
		when(azureFactory.fetchPublicKey(any())).thenReturn(publicKey);
		UUID id = seedActiveLocalCa();

		CaConfig active = caConfigService.rotate(id, ACTOR, "azure_keyvault",
				"https://myvault.vault.azure.net/keys/session-ca/" + VERSION, "ecdsa-p256").block();

		assertThat(active.backend()).isEqualTo("azure_keyvault");
		assertThat(active.keyReference()).isEqualTo("https://myvault.vault.azure.net/keys/session-ca/" + VERSION);
		assertThat(active.algorithm()).isEqualTo("ecdsa-p256");
		assertThat(active.rotationState()).isEqualTo("active");
		assertThat(active.id()).isNotEqualTo(id);

		CaKeyMaterial material = caKeyMaterials.findByCaConfigId(active.id()).block();
		assertThat(material).isNotNull();
		assertThat(material.keyLocation()).isEqualTo(CaKeyMaterial.EXTERNAL);
		assertThat(material.wrappedKey()).isNull();
		assertThat(material.iv()).isNull();
		assertThat(material.kekReference()).isNull();
		assertThat(material.publicKey()).isEqualTo(publicKey.getEncoded());
	}

	/**
	 * {@code CaConfigService.validate} now calls {@code KeyVaultKeyReference.parse}
	 * itself (pre-commit, before {@code rotation.provisionIncoming} is ever
	 * reached), so this surfaces as {@link ApiProblemException} at the service
	 * boundary rather than the raw {@code InvalidKeyReference}
	 * {@link AzureKeyVaultCaProvisioner} would throw if it were ever reached
	 * directly - belt and suspenders: the provisioner's own parse is defense in
	 * depth for any caller that does not pre-validate.
	 */
	@Test
	void aVersionLessReferenceIsRefusedAtRotationAndWritesNothing() {
		when(azureFactory.vaultUri()).thenReturn(VAULT_URI);
		UUID id = seedActiveLocalCa();
		long before = caConfigs.count().block();

		assertThatThrownBy(() -> caConfigService
				.rotate(id, ACTOR, "azure_keyvault", "https://myvault.vault.azure.net/keys/session-ca", "ecdsa-p256")
				.block()).isInstanceOf(ApiProblemException.class).hasMessageContaining("no key version");

		assertThat(caConfigs.count().block()).isEqualTo(before);
		CaConfig stillActive = caConfigs.findByCaKindAndRotationState("session", "active").block();
		assertThat(stillActive.id()).isEqualTo(id);
		assertThat(stillActive.backend()).isEqualTo("local");
	}

	@Test
	void aReferenceNamingADifferentVaultIsRefusedAtRotationAndWritesNothing() {
		when(azureFactory.vaultUri()).thenReturn(VAULT_URI);
		UUID id = seedActiveLocalCa();
		long before = caConfigs.count().block();

		assertThatThrownBy(
				() -> caConfigService
						.rotate(id, ACTOR, "azure_keyvault",
								"https://attacker-vault.vault.azure.net/keys/session-ca/" + VERSION, "ecdsa-p256")
						.block())
				.isInstanceOf(ApiProblemException.class).hasMessageContaining("only the configured vault is permitted");

		assertThat(caConfigs.count().block()).isEqualTo(before);
	}

	@Test
	void aMalformedKeyVersionIsRefusedAtRotationAndWritesNothing() {
		when(azureFactory.vaultUri()).thenReturn(VAULT_URI);
		UUID id = seedActiveLocalCa();
		long before = caConfigs.count().block();

		assertThatThrownBy(() -> caConfigService
				.rotate(id, ACTOR, "azure_keyvault", "https://myvault.vault.azure.net/keys/session-ca/v1", "ecdsa-p256")
				.block()).isInstanceOf(ApiProblemException.class).hasMessageContaining("invalid key version");

		assertThat(caConfigs.count().block()).isEqualTo(before);
	}
}
