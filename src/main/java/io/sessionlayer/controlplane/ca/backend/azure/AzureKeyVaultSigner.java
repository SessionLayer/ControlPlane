package io.sessionlayer.controlplane.ca.backend.azure;

import com.azure.security.keyvault.keys.cryptography.CryptographyClient;
import com.azure.security.keyvault.keys.cryptography.models.SignatureAlgorithm;
import io.sessionlayer.controlplane.ca.CaKeyType;
import io.sessionlayer.controlplane.ca.backend.CaSigningFailedException;
import io.sessionlayer.controlplane.ca.sign.EcdsaSignatures;
import java.security.GeneralSecurityException;
import java.security.Signature;
import java.security.interfaces.ECPublicKey;

/**
 * Production {@link KeyVaultSigner}: a {@link CryptographyClient} bound to one
 * pinned key version, plus the pinned public key (resolved from
 * {@code ca_key_material.public_key} at adoption — never re-fetched here, so
 * construction stays network-free).
 *
 * <p>
 * Every signature is verified locally against the pinned key before it is
 * returned. This is what turns "the vault key is pinned" from a documented
 * intent into an enforced one: a vault that signed with a different key,
 * returned the wrong shape, or returned garbage all fail closed here, at the
 * point of signing, instead of at the far end of the fleet when a node refuses
 * a certificate it does not trust.
 */
public final class AzureKeyVaultSigner implements KeyVaultSigner {

	private final CryptographyClient client;
	private final ECPublicKey publicKey;
	private final String keyReference;

	public AzureKeyVaultSigner(CryptographyClient client, ECPublicKey publicKey, String keyReference) {
		this.client = client;
		this.publicKey = publicKey;
		this.keyReference = keyReference;
	}

	@Override
	public ECPublicKey publicKey() {
		return publicKey;
	}

	@Override
	public byte[] signDigestP1363(byte[] sha256Digest) {
		if (sha256Digest.length != 32) {
			throw new KeyVaultSigningException(keyReference,
					"digest must be exactly 32 bytes (SHA-256), got " + sha256Digest.length);
		}
		byte[] signature;
		try {
			signature = client.sign(SignatureAlgorithm.ES256, sha256Digest).getSignature();
		} catch (RuntimeException e) {
			// getMessage() is built from the key reference and the exception's
			// class name only, so it is safe to propagate into an API error or a
			// span; the SDK exception is kept as the cause purely for an operator
			// reading a full stack trace, where its own message (a Key Vault error
			// body, not a credential or key) is legitimately useful.
			throw new KeyVaultSigningException(keyReference, e);
		}
		if (!verifiesAgainstPinnedKey(signature, sha256Digest)) {
			throw new KeyVaultSigningException(keyReference,
					"returned signature does not verify against the pinned public key");
		}
		return signature;
	}

	private boolean verifiesAgainstPinnedKey(byte[] p1363Signature, byte[] digest) {
		try {
			// ECDSA_NISTP256 is hardcoded, not carried on this signer, because
			// CaBackendCapabilities.forBackend("azure_keyvault") permits only P-256
			// today; if that table ever widens, this constant must move with it or
			// a wider key type verifies with the wrong coordinate length (fails
			// closed, but confusingly).
			EcdsaSignatures.RS rs = EcdsaSignatures.fromP1363(p1363Signature, CaKeyType.ECDSA_NISTP256);
			byte[] der = EcdsaSignatures.toDer(rs);
			Signature verifier = Signature.getInstance("NONEwithECDSA");
			verifier.initVerify(publicKey);
			verifier.update(digest);
			return verifier.verify(der);
		} catch (IllegalArgumentException | GeneralSecurityException malformed) {
			return false;
		}
	}

	/**
	 * Fail-closed signing failure (FR-CA-9). {@code getMessage()} never carries
	 * vault response content — only the key reference and the failure's class name
	 * — so it is safe wherever a message alone is surfaced (an API error, a span).
	 * The cause, when present, is the real SDK exception and is kept on purpose for
	 * operator diagnosis; a full stack trace dump is expected to show it.
	 */
	public static final class KeyVaultSigningException extends CaSigningFailedException {
		KeyVaultSigningException(String keyReference, Throwable cause) {
			super("Key Vault signing failed for key '" + keyReference + "' (" + cause.getClass().getSimpleName() + ")",
					cause);
		}

		KeyVaultSigningException(String keyReference, String reason) {
			super("Key Vault signing failed for key '" + keyReference + "': " + reason);
		}
	}
}
