package io.sessionlayer.controlplane.ca.mtls;

import java.math.BigInteger;
import java.security.PublicKey;
import java.time.Instant;
import java.util.List;

public record LeafCertificateSpec(PublicKey subjectPublicKey, String subjectCommonName, List<String> dnsSans,
		List<String> uriSans, LeafPurpose purpose, BigInteger serial, Instant notBefore, Instant notAfter) {

	public LeafCertificateSpec {
		if (subjectPublicKey == null) {
			throw new IllegalArgumentException("subjectPublicKey is required");
		}
		if (subjectCommonName == null || subjectCommonName.isBlank()) {
			throw new IllegalArgumentException("subjectCommonName is required");
		}
		if (purpose == null) {
			throw new IllegalArgumentException("purpose is required");
		}
		if (serial == null || serial.signum() <= 0) {
			throw new IllegalArgumentException("serial must be positive");
		}
		if (notBefore == null || notAfter == null || !notAfter.isAfter(notBefore)) {
			throw new IllegalArgumentException("notAfter must be after notBefore");
		}
		dnsSans = (dnsSans == null) ? List.of() : List.copyOf(dnsSans);
		uriSans = (uriSans == null) ? List.of() : List.copyOf(uriSans);
	}
}
