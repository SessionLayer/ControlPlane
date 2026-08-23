package io.sessionlayer.controlplane.ca.backend.azure;

import java.security.interfaces.ECPublicKey;

public interface KeyVaultSigner {

	ECPublicKey publicKey();

	byte[] signDigestP1363(byte[] sha256Digest);
}
