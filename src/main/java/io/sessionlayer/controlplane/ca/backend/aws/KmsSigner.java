package io.sessionlayer.controlplane.ca.backend.aws;

import java.security.interfaces.ECPublicKey;

/**
 * The injectable seam for AWS KMS. {@link AwsKmsSigner} binds it to the AWS SDK
 * v2 {@code KmsClient.sign(...)} with {@code SigningAlgorithm = ECDSA_SHA_256}
 * and {@code MessageType = DIGEST}; that call returns a <b>DER</b>-encoded
 * {@code SEQUENCE{INTEGER r, INTEGER s}} which {@link KmsCaBackend} normalizes.
 */
public interface KmsSigner {

	/** The CA public key resolved from KMS (e.g. via {@code GetPublicKey}). */
	ECPublicKey publicKey();

	/**
	 * Sign a SHA-256 <b>digest</b> with the KMS key ({@code ECDSA_SHA_256}) and
	 * return the DER-encoded signature. MUST throw on failure (fail closed).
	 */
	byte[] signDigestDer(byte[] sha256Digest);
}
