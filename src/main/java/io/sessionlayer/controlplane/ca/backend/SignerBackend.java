package io.sessionlayer.controlplane.ca.backend;

import io.sessionlayer.controlplane.ca.CaKeyType;
import io.sessionlayer.controlplane.ca.SignerCapabilities;
import io.sessionlayer.controlplane.ca.sign.EcdsaSignatures;
import java.security.interfaces.ECPublicKey;

/**
 * The injectable raw-signer seam. A backend holds (or references) a CA key and
 * turns to-be-signed bytes into a <b>normalized</b> ECDSA {@code (r, s)} — each
 * backend converts its native signature shape (Java/KMS DER, Azure P1363) to
 * {@code (r, s)} so the shared assembler is backend-agnostic.
 *
 * <p>
 * Implementations MUST fail closed (throw) if they cannot sign — never return a
 * wrong or empty signature. The Vault SSH-engine path does not use this seam
 * (it returns a signed cert directly).
 */
public interface SignerBackend {

	CaKeyType keyType();

	ECPublicKey publicKey();

	SignerCapabilities capabilities();

	EcdsaSignatures.RS sign(byte[] toBeSigned);
}
