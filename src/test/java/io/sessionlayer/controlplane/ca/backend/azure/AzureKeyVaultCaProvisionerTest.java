package io.sessionlayer.controlplane.ca.backend.azure;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import io.sessionlayer.controlplane.ca.CaBackendCapabilities;
import io.sessionlayer.controlplane.ca.CaKeyProvisioner;
import io.sessionlayer.controlplane.ca.CaKeyProvisioner.Request;
import io.sessionlayer.controlplane.ca.backend.azure.KeyVaultKeyReference.InvalidKeyReference;
import io.sessionlayer.controlplane.data.config.CaConfig;
import io.sessionlayer.controlplane.data.runtime.CaKeyMaterial;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import org.junit.jupiter.api.Test;

class AzureKeyVaultCaProvisionerTest {

	private static final String VAULT_URI = "https://myvault.vault.azure.net";

	/** A well-formed Key Vault version: 32 lowercase hex characters. */
	private static final String VERSION = "abcdef0123456789abcdef0123456789";

	private static ECPublicKey ecPublicKey() {
		try {
			KeyPairGenerator g = KeyPairGenerator.getInstance("EC");
			g.initialize(new ECGenParameterSpec("secp256r1"));
			KeyPair pair = g.generateKeyPair();
			return (ECPublicKey) pair.getPublic();
		} catch (Exception e) {
			throw new IllegalStateException(e);
		}
	}

	private static AzureKeyVaultSignerFactory factoryReturning(ECPublicKey publicKey) {
		AzureKeyVaultSignerFactory factory = mock(AzureKeyVaultSignerFactory.class);
		when(factory.vaultUri()).thenReturn(VAULT_URI);
		when(factory.fetchPublicKey(any())).thenReturn(publicKey);
		return factory;
	}

	@Test
	void backendIsAzureKeyvault() {
		assertThat(new AzureKeyVaultCaProvisioner(mock(AzureKeyVaultSignerFactory.class)).backend())
				.isEqualTo("azure_keyvault");
	}

	@Test
	void provisionsFromAValidVersionedReferenceMatchingTheConfiguredVault() {
		ECPublicKey publicKey = ecPublicKey();
		AzureKeyVaultSignerFactory factory = factoryReturning(publicKey);
		AzureKeyVaultCaProvisioner provisioner = new AzureKeyVaultCaProvisioner(factory);

		CaKeyProvisioner.Provisioned result = provisioner.provision(new Request("session", "session-ca", "incoming",
				"https://myvault.vault.azure.net/keys/ssh-ca/" + VERSION + "?api-version=7.4", "ecdsa-p256"));

		CaConfig config = result.config();
		assertThat(config.backend()).isEqualTo("azure_keyvault");
		assertThat(config.caKind()).isEqualTo("session");
		assertThat(config.rotationState()).isEqualTo("incoming");
		assertThat(config.algorithm()).isEqualTo("ecdsa-p256");
		// Canonical, not the raw input string: the query string is gone, proving
		// this is rebuilt from the parsed KeyVaultKeyReference rather than persisted
		// verbatim from an attacker- or operator-supplied string.
		assertThat(config.keyReference()).isEqualTo("https://myvault.vault.azure.net/keys/ssh-ca/" + VERSION);

		CaKeyMaterial material = result.material();
		assertThat(material.caConfigId()).isEqualTo(config.id());
		assertThat(material.keyLocation()).isEqualTo(CaKeyMaterial.EXTERNAL);
		assertThat(material.wrappedKey()).isNull();
		assertThat(material.iv()).isNull();
		assertThat(material.kekReference()).isNull();
		assertThat(material.publicKey()).isEqualTo(publicKey.getEncoded());
		assertThat(material.keyType()).isEqualTo("ecdsa-sha2-nistp256");
	}

	@Test
	void refusesAVersionLessReferenceBeforeEverCallingTheVault() {
		AzureKeyVaultSignerFactory factory = factoryReturning(ecPublicKey());
		AzureKeyVaultCaProvisioner provisioner = new AzureKeyVaultCaProvisioner(factory);

		assertThatThrownBy(() -> provisioner.provision(new Request("session", "session-ca", "incoming",
				"https://myvault.vault.azure.net/keys/ssh-ca", "ecdsa-p256"))).isInstanceOf(InvalidKeyReference.class);

		// vaultUri() is called to build the allow-list anchor argument itself;
		// fetchPublicKey is the actual vault call, and it must never happen.
		verify(factory, org.mockito.Mockito.never()).fetchPublicKey(any());
	}

	@Test
	void refusesAReferenceNamingADifferentVaultBeforeEverCallingTheVault() {
		AzureKeyVaultSignerFactory factory = factoryReturning(ecPublicKey());
		AzureKeyVaultCaProvisioner provisioner = new AzureKeyVaultCaProvisioner(factory);

		assertThatThrownBy(() -> provisioner.provision(new Request("session", "session-ca", "incoming",
				"https://attacker-vault.vault.azure.net/keys/ssh-ca/" + VERSION, "ecdsa-p256")))
				.isInstanceOf(InvalidKeyReference.class);

		verify(factory, org.mockito.Mockito.never()).fetchPublicKey(any());
	}

	@Test
	void refusesAnUnsupportedAlgorithmWithoutParsingTheReferenceOrCallingTheVault() {
		AzureKeyVaultSignerFactory factory = factoryReturning(ecPublicKey());
		AzureKeyVaultCaProvisioner provisioner = new AzureKeyVaultCaProvisioner(factory);

		assertThatThrownBy(() -> provisioner.provision(new Request("session", "session-ca", "incoming",
				"https://myvault.vault.azure.net/keys/ssh-ca/" + VERSION, "ed25519")))
				.isInstanceOf(CaBackendCapabilities.AlgorithmNotSupported.class);

		verifyNoInteractions(factory);
	}
}
