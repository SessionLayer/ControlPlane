package io.sessionlayer.controlplane.ca.backend.azure;

import com.azure.security.keyvault.keys.cryptography.CryptographyClient;
import com.azure.security.keyvault.keys.cryptography.models.SignatureAlgorithm;
import io.sessionlayer.controlplane.ca.CaKeyType;
import io.sessionlayer.controlplane.ca.backend.CaSigningFailedException;
import io.sessionlayer.controlplane.ca.sign.EcdsaSignatures;
import java.security.GeneralSecurityException;
import java.security.Signature;
import java.security.interfaces.ECPublicKey;

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
