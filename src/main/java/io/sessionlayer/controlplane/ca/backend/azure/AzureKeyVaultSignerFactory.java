package io.sessionlayer.controlplane.ca.backend.azure;

import com.azure.core.credential.TokenCredential;
import com.azure.core.http.HttpClient;
import com.azure.core.http.jdk.httpclient.JdkHttpClientBuilder;
import com.azure.identity.DefaultAzureCredentialBuilder;
import com.azure.identity.ManagedIdentityCredentialBuilder;
import com.azure.identity.WorkloadIdentityCredentialBuilder;
import com.azure.security.keyvault.keys.KeyClient;
import com.azure.security.keyvault.keys.KeyClientBuilder;
import com.azure.security.keyvault.keys.cryptography.CryptographyClient;
import com.azure.security.keyvault.keys.cryptography.CryptographyClientBuilder;
import com.azure.security.keyvault.keys.models.JsonWebKey;
import com.azure.security.keyvault.keys.models.KeyCurveName;
import com.azure.security.keyvault.keys.models.KeyOperation;
import com.azure.security.keyvault.keys.models.KeyType;
import com.azure.security.keyvault.keys.models.KeyVaultKey;
import java.security.KeyPair;
import java.security.interfaces.ECPublicKey;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBooleanProperty;
import org.springframework.stereotype.Component;

/**
 * Builds {@link KeyVaultSigner}s and resolves adoption-time public keys.
 * Present only when {@code sessionlayer.ca.azure.enabled=true} — its absence as
 * a bean IS the "Azure support not configured" branch {@code CaSignerService}
 * refuses on, so there is nothing here that quietly degrades.
 *
 * <p>
 * The {@link TokenCredential} and the JDK {@link HttpClient} are built once, at
 * bean construction, and building them does no I/O — the SDK resolves the
 * credential chain and opens no connection until a request is made (proven by
 * {@code AzureCredentialsSmokeTest}). One exception: {@code WORKLOAD_IDENTITY}
 * validates its AKS-injected properties (tenant id, federated token file path)
 * eagerly and throws if they are absent, still without touching the network —
 * off an actual Workload-Identity-Federated pod this fails the bean at
 * construction, which is the correct fail-closed shape for that credential, not
 * a defect. Signer construction ({@link #signerFor}) is likewise I/O-free: only
 * {@link #fetchPublicKey}, used solely at CA adoption, talks to the vault.
 */
@Component
@ConditionalOnBooleanProperty(name = "sessionlayer.ca.azure.enabled")
public class AzureKeyVaultSignerFactory {

	private final AzureKeyVaultProperties properties;
	private final TokenCredential credential;
	private final HttpClient httpClient;
	private final ConcurrentHashMap<String, CryptographyClient> cryptographyClients = new ConcurrentHashMap<>();

	public AzureKeyVaultSignerFactory(AzureKeyVaultProperties properties) {
		this.properties = properties;
		this.credential = buildCredential(properties);
		this.httpClient = new JdkHttpClientBuilder().connectionTimeout(properties.getTimeout())
				.responseTimeout(properties.getTimeout()).build();
	}

	/**
	 * The one vault this Control Plane signs in — the allow-list anchor
	 * {@link KeyVaultKeyReference} enforces.
	 */
	public String vaultUri() {
		return properties.getVaultUri();
	}

	/**
	 * A {@link KeyVaultSigner} bound to {@code ref}'s pinned key version and
	 * {@code pinnedPublicKey} (read from {@code ca_key_material}, never re-fetched
	 * here). The underlying {@link CryptographyClient} is cached per key identifier
	 * so repeated signing does not rebuild the HTTP pipeline.
	 */
	public KeyVaultSigner signerFor(KeyVaultKeyReference ref, ECPublicKey pinnedPublicKey) {
		CryptographyClient client = cryptographyClients.computeIfAbsent(ref.keyIdentifier(),
				keyIdentifier -> new CryptographyClientBuilder().keyIdentifier(keyIdentifier).credential(credential)
						.httpClient(httpClient).buildClient());
		return new AzureKeyVaultSigner(client, pinnedPublicKey, ref.keyIdentifier());
	}

	/**
	 * Resolves the public key for {@code ref} directly from Key Vault. Used only at
	 * CA adoption (rotation onto a Key Vault key) — every other read of the CA
	 * public key is the persisted {@code ca_key_material.public_key} column, so
	 * this is the sole point where the vault is asked "what is this key".
	 */
	public ECPublicKey fetchPublicKey(KeyVaultKeyReference ref) {
		KeyClient keyClient = new KeyClientBuilder().vaultUrl(ref.vaultUrl()).credential(credential)
				.httpClient(httpClient).buildClient();
		KeyVaultKey key = keyClient.getKey(ref.keyName(), ref.keyVersion());
		assertRequestedKeyReturned(ref, key);
		JsonWebKey jwk = key.getKey();
		validateSigningKey(jwk, ref.keyIdentifier());
		KeyPair pair = jwk.toEc(false);
		return (ECPublicKey) pair.getPublic();
	}

	/**
	 * The result of {@link #fetchPublicKey} becomes the pinned public key persisted
	 * into {@code ca_key_material}, so this is the one hop in the whole design that
	 * is not otherwise verified: a vault, proxy, or redirect returning a different
	 * key (or a different <b>version</b> of the same key) would silently pin the CA
	 * to a key the operator never chose, and every later signature would then
	 * verify against it perfectly.
	 */
	static void assertRequestedKeyReturned(KeyVaultKeyReference ref, KeyVaultKey key) {
		if (!ref.keyIdentifier().equals(key.getId())) {
			throw new IllegalStateException("Key Vault returned a key id '" + key.getId()
					+ "' that does not match the requested '" + ref.keyIdentifier() + "'");
		}
	}

	/**
	 * Package-visible for {@code AzureKeyVaultSignerFactoryTest}: the EC/P-256/sign
	 * checks are pure, so they are proven without a vault, independent of the
	 * network call in {@link #fetchPublicKey}.
	 */
	static void validateSigningKey(JsonWebKey jwk, String keyIdentifier) {
		KeyType keyType = jwk.getKeyType();
		if (!KeyType.EC.equals(keyType) && !KeyType.EC_HSM.equals(keyType)) {
			throw new IllegalStateException("Key Vault key '" + keyIdentifier + "' is type " + keyType + ", not EC");
		}
		if (!KeyCurveName.P_256.equals(jwk.getCurveName())) {
			throw new IllegalStateException(
					"Key Vault key '" + keyIdentifier + "' curve is " + jwk.getCurveName() + ", not P-256");
		}
		List<KeyOperation> operations = jwk.getKeyOps();
		if (operations == null || !operations.contains(KeyOperation.SIGN)) {
			throw new IllegalStateException("Key Vault key '" + keyIdentifier + "' does not permit the sign operation");
		}
	}

	private static TokenCredential buildCredential(AzureKeyVaultProperties properties) {
		String clientId = properties.getClientId();
		boolean pinClientId = clientId != null && !clientId.isBlank();
		return switch (properties.getCredential()) {
			case DEFAULT -> {
				DefaultAzureCredentialBuilder builder = new DefaultAzureCredentialBuilder();
				if (pinClientId) {
					builder.managedIdentityClientId(clientId);
				}
				yield builder.build();
			}
			case MANAGED_IDENTITY -> {
				ManagedIdentityCredentialBuilder builder = new ManagedIdentityCredentialBuilder();
				if (pinClientId) {
					builder.clientId(clientId);
				}
				yield builder.build();
			}
			case WORKLOAD_IDENTITY -> {
				WorkloadIdentityCredentialBuilder builder = new WorkloadIdentityCredentialBuilder();
				if (pinClientId) {
					builder.clientId(clientId);
				}
				yield builder.build();
			}
		};
	}
}
