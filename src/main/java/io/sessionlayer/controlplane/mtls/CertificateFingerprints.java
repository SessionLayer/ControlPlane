package io.sessionlayer.controlplane.mtls;

import java.security.MessageDigest;
import java.security.cert.X509Certificate;
import java.util.HexFormat;

public final class CertificateFingerprints {

	private CertificateFingerprints() {
	}

	public static String sha256Hex(X509Certificate certificate) {
		try {
			byte[] digest = MessageDigest.getInstance("SHA-256").digest(certificate.getEncoded());
			return HexFormat.of().formatHex(digest);
		} catch (Exception e) {
			throw new IllegalStateException("failed to fingerprint certificate", e);
		}
	}
}
