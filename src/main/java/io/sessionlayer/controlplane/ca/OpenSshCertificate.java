package io.sessionlayer.controlplane.ca;

import java.util.Base64;

public record OpenSshCertificate(CaKeyType keyType, byte[] blob, String certificateLine, long serial, String keyId) {

	public String base64() {
		return Base64.getEncoder().encodeToString(blob);
	}
}
