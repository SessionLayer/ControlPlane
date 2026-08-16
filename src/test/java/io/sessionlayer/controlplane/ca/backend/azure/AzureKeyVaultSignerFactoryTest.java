package io.sessionlayer.controlplane.ca.backend.azure;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.azure.security.keyvault.keys.models.JsonWebKey;
import com.azure.security.keyvault.keys.models.KeyCurveName;
import com.azure.security.keyvault.keys.models.KeyOperation;
import com.azure.security.keyvault.keys.models.KeyType;
import com.azure.security.keyvault.keys.models.KeyVaultKey;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import org.junit.jupiter.api.Test;

class AzureKeyVaultSignerFactoryTest {

	private static AzureKeyVaultProperties properties(AzureKeyVaultProperties.Credential credential, String clientId) {
		AzureKeyVaultProperties properties = new AzureKeyVaultProperties();
		properties.setEnabled(true);
		properties.setVaultUri("https://myvault.vault.azure.net");
		properties.setCredential(credential);
		properties.setClientId(clientId);
		return properties;
	}

	@Test
	void buildsWithTheDefaultCredentialChain() {
		assertThatCode(
				() -> new AzureKeyVaultSignerFactory(properties(AzureKeyVaultProperties.Credential.DEFAULT, null)))
				.doesNotThrowAnyException();
	}

	@Test
	void buildsWithAPinnedUserAssignedManagedIdentity() {
		assertThatCode(
				() -> new AzureKeyVaultSignerFactory(properties(AzureKeyVaultProperties.Credential.MANAGED_IDENTITY,
						"11111111-1111-1111-1111-111111111111")))
				.doesNotThrowAnyException();
	}

	/**
	 * Unlike {@code DEFAULT}/{@code MANAGED_IDENTITY},
	 * {@code WorkloadIdentityCredentialBuilder.build()} validates its AKS-injected
	 * properties (tenant id, federated token file path) eagerly and throws if they
	 * are absent — still I/O-free (no network call), but not silent like the other
	 * two. Outside a real AKS pod under Workload Identity Federation those
	 * properties are unset, so this is the credential failing closed at
	 * construction, which is what a build with this credential SHOULD do
	 * off-cluster: fail the bean, not sign with nothing.
	 */
	@Test
	void workloadIdentityFailsClosedWithoutTheAksInjectedEnvironment() {
		assertThatThrownBy(() -> new AzureKeyVaultSignerFactory(
				properties(AzureKeyVaultProperties.Credential.WORKLOAD_IDENTITY, null)))
				.isInstanceOf(IllegalArgumentException.class).hasMessageContaining("Tenant ID");
	}

	@Test
	void exposesTheConfiguredVaultUriAsTheAllowListAnchor() {
		AzureKeyVaultSignerFactory factory = new AzureKeyVaultSignerFactory(
				properties(AzureKeyVaultProperties.Credential.DEFAULT, null));
		assertThat(factory.vaultUri()).isEqualTo("https://myvault.vault.azure.net");
	}

	@Test
	void acceptsAnEcP256KeyThatPermitsSign() {
		JsonWebKey jwk = new JsonWebKey().setKeyType(KeyType.EC).setCurveName(KeyCurveName.P_256)
				.setKeyOps(List.of(KeyOperation.SIGN, KeyOperation.VERIFY));
		assertThatCode(() -> AzureKeyVaultSignerFactory.validateSigningKey(jwk, "key-ref")).doesNotThrowAnyException();
	}

	@Test
	void acceptsAnEcHsmP256Key() {
		JsonWebKey jwk = new JsonWebKey().setKeyType(KeyType.EC_HSM).setCurveName(KeyCurveName.P_256)
				.setKeyOps(List.of(KeyOperation.SIGN));
		assertThatCode(() -> AzureKeyVaultSignerFactory.validateSigningKey(jwk, "key-ref")).doesNotThrowAnyException();
	}

	@Test
	void rejectsANonEcKey() {
		JsonWebKey jwk = new JsonWebKey().setKeyType(KeyType.RSA).setKeyOps(List.of(KeyOperation.SIGN));
		assertThatThrownBy(() -> AzureKeyVaultSignerFactory.validateSigningKey(jwk, "key-ref"))
				.isInstanceOf(IllegalStateException.class).hasMessageContaining("not EC");
	}

	@Test
	void rejectsAnEcKeyOnTheWrongCurve() {
		JsonWebKey jwk = new JsonWebKey().setKeyType(KeyType.EC).setCurveName(KeyCurveName.P_384)
				.setKeyOps(List.of(KeyOperation.SIGN));
		assertThatThrownBy(() -> AzureKeyVaultSignerFactory.validateSigningKey(jwk, "key-ref"))
				.isInstanceOf(IllegalStateException.class).hasMessageContaining("not P-256");
	}

	@Test
	void rejectsAKeyThatCannotSign() {
		JsonWebKey jwk = new JsonWebKey().setKeyType(KeyType.EC).setCurveName(KeyCurveName.P_256)
				.setKeyOps(List.of(KeyOperation.VERIFY));
		assertThatThrownBy(() -> AzureKeyVaultSignerFactory.validateSigningKey(jwk, "key-ref"))
				.isInstanceOf(IllegalStateException.class).hasMessageContaining("does not permit the sign operation");
	}

	@Test
	void rejectsAKeyWithNoOperationsListed() {
		JsonWebKey jwk = new JsonWebKey().setKeyType(KeyType.EC).setCurveName(KeyCurveName.P_256);
		assertThatThrownBy(() -> AzureKeyVaultSignerFactory.validateSigningKey(jwk, "key-ref"))
				.isInstanceOf(IllegalStateException.class).hasMessageContaining("does not permit the sign operation");
	}

	/**
	 * Two well-formed, distinct Key Vault versions: 32 lowercase hex characters.
	 */
	private static final String VERSION_1 = "abcdef0123456789abcdef0123456789";
	private static final String VERSION_2 = "abcdef0123456789abcdef0123456780";

	@Test
	void acceptsTheKeyVaultReturnsWhenItsIdMatchesTheRequestedReference() {
		KeyVaultKeyReference ref = KeyVaultKeyReference
				.parse("https://myvault.vault.azure.net/keys/ssh-ca/" + VERSION_1, "https://myvault.vault.azure.net");
		KeyVaultKey key = mock(KeyVaultKey.class);
		when(key.getId()).thenReturn("https://myvault.vault.azure.net/keys/ssh-ca/" + VERSION_1);

		assertThatCode(() -> AzureKeyVaultSignerFactory.assertRequestedKeyReturned(ref, key))
				.doesNotThrowAnyException();
	}

	/**
	 * The public key {@code fetchPublicKey} resolves becomes the pinned trust
	 * anchor for the whole CA, so a vault (or a redirect, or a proxy) answering
	 * with a different key id — even a different version of the SAME key name —
	 * must be refused rather than silently pinned.
	 */
	@Test
	void rejectsAKeyVaultResponseWhoseIdDoesNotMatchTheRequestedReference() {
		KeyVaultKeyReference ref = KeyVaultKeyReference
				.parse("https://myvault.vault.azure.net/keys/ssh-ca/" + VERSION_1, "https://myvault.vault.azure.net");
		KeyVaultKey key = mock(KeyVaultKey.class);
		when(key.getId()).thenReturn("https://myvault.vault.azure.net/keys/ssh-ca/" + VERSION_2);

		assertThatThrownBy(() -> AzureKeyVaultSignerFactory.assertRequestedKeyReturned(ref, key))
				.isInstanceOf(IllegalStateException.class).hasMessageContaining(VERSION_1)
				.hasMessageContaining(VERSION_2);
	}

	/**
	 * The SDK's challenge-resource check (a returned challenge's {@code resource}
	 * must be a parent domain of the request host) is an anti-token-exfiltration
	 * control. Disabling it is a legitimate thing for a test client pointed at a
	 * non-Azure-domain double to do, but it must never migrate into the production
	 * factory — a source scan pins that even though nothing here can unit-test the
	 * real credential/challenge exchange without a vault. This is a tripwire
	 * against the obvious mistake (the literal call appearing in this file), not a
	 * proof: it would not catch the flag being set through a builder reference held
	 * in a variable, or through a differently-named helper.
	 */
	@Test
	void theProductionFactoryNeverDisablesChallengeResourceVerification() throws IOException {
		String source = Files.readString(
				Path.of("src/main/java/io/sessionlayer/controlplane/ca/backend/azure/AzureKeyVaultSignerFactory.java"));
		assertThat(source).doesNotContain("disableChallengeResourceVerification");
	}
}
