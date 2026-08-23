package io.sessionlayer.controlplane.ca.backend.aws;

import java.security.interfaces.ECPublicKey;

public interface KmsSigner {

	ECPublicKey publicKey();

	byte[] signDigestDer(byte[] sha256Digest);
}
