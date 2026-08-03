package io.sessionlayer.controlplane.ca.backend.aws;

import io.sessionlayer.controlplane.ca.backend.CaSigningFailedException;
import java.security.GeneralSecurityException;
import java.security.Signature;
import java.security.interfaces.ECPublicKey;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.model.MessageType;
import software.amazon.awssdk.services.kms.model.SignRequest;
import software.amazon.awssdk.services.kms.model.SignResponse;
import software.amazon.awssdk.services.kms.model.SigningAlgorithmSpec;

/**
 * Production {@link KmsSigner}: a shared {@link KmsClient} plus the one key ARN
 * this signer may name, and the pinned public key (resolved from
 * {@code ca_key_material.public_key} at adoption — never re-fetched here, so
 * construction stays network-free).
 *
 * <p>
 * Every signature is verified locally against the pinned key before it is
 * returned. This is what turns "the KMS key is pinned" from a documented intent
 * into an enforced one: KMS signing with a different key, returning the wrong
 * encoding, or returning truncated bytes all fail closed here, at the point of
 * signing, instead of at the far end of the fleet when a node refuses a
 * certificate it does not trust.
 */
public final class AwsKmsSigner implements KmsSigner {

	private final KmsClient kms;
	private final ECPublicKey publicKey;
	private final String keyArn;

	public AwsKmsSigner(KmsClient kms, ECPublicKey publicKey, String keyArn) {
		this.kms = kms;
		this.publicKey = publicKey;
		this.keyArn = keyArn;
	}

	@Override
	public ECPublicKey publicKey() {
		return publicKey;
	}

	@Override
	public byte[] signDigestDer(byte[] sha256Digest) {
		if (sha256Digest.length != 32) {
			throw new KmsSigningException(keyArn,
					"digest must be exactly 32 bytes (SHA-256), got " + sha256Digest.length);
		}
		SignResponse response;
		try {
			response = kms.sign(SignRequest.builder().keyId(keyArn).signingAlgorithm(SigningAlgorithmSpec.ECDSA_SHA_256)
					.messageType(MessageType.DIGEST).message(SdkBytes.fromByteArray(sha256Digest)).build());
		} catch (RuntimeException e) {
			// getMessage() is built from the key ARN and the exception's class name
			// only, so it is safe to propagate into an API error or a span; the SDK
			// exception is kept as the cause purely for an operator reading a full
			// stack trace, where its own message (a KMS error body, not a credential
			// or key) is legitimately useful.
			throw new KmsSigningException(keyArn, e);
		}
		if (!keyArn.equals(response.keyId())) {
			// The returned id is deliberately not echoed: it is whatever answered,
			// and the only fact worth reporting is that it was not the pinned key.
			throw new KmsSigningException(keyArn, "the signature is attributed to a different key than the pinned one");
		}
		if (SigningAlgorithmSpec.ECDSA_SHA_256 != response.signingAlgorithm()) {
			throw new KmsSigningException(keyArn,
					"signature was produced with " + response.signingAlgorithm() + ", not ECDSA_SHA_256");
		}
		byte[] signature = response.signature().asByteArray();
		if (!verifiesAgainstPinnedKey(signature, sha256Digest)) {
			throw new KmsSigningException(keyArn, "returned signature does not verify against the pinned public key");
		}
		return signature;
	}

	// The digest is verified as the message under NONEwithECDSA, which is also
	// what refuses a P1363 r||s signature in the DER position: the JCA verifier
	// reads DER, so an unwrapped pair fails to decode and fails closed. That
	// discrimination is the whole point of KmsCaBackend's fromDer normalization,
	// so it cannot be left to a shape check that both encodings would pass.
	private boolean verifiesAgainstPinnedKey(byte[] derSignature, byte[] digest) {
		try {
			Signature verifier = Signature.getInstance("NONEwithECDSA");
			verifier.initVerify(publicKey);
			verifier.update(digest);
			return verifier.verify(derSignature);
		} catch (IllegalArgumentException | GeneralSecurityException malformed) {
			return false;
		}
	}

	/**
	 * Fail-closed signing failure (FR-CA-9). {@code getMessage()} never carries KMS
	 * response content — only the key ARN and the failure's class name — so it is
	 * safe wherever a message alone is surfaced (an API error, a span). The cause,
	 * when present, is the real SDK exception and is kept on purpose for operator
	 * diagnosis; a full stack trace dump is expected to show it.
	 */
	public static final class KmsSigningException extends CaSigningFailedException {
		KmsSigningException(String keyArn, Throwable cause) {
			super("KMS signing failed for key '" + keyArn + "' (" + cause.getClass().getSimpleName() + ")", cause);
		}

		KmsSigningException(String keyArn, String reason) {
			super("KMS signing failed for key '" + keyArn + "': " + reason);
		}
	}
}
