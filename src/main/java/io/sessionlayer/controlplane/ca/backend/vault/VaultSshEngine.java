package io.sessionlayer.controlplane.ca.backend.vault;

import java.util.List;
import java.util.Map;

/**
 * The injectable seam for the HashiCorp Vault SSH secrets engine. There is
 * deliberately <b>only a sign operation</b>: production binds it to
 * {@code POST /v1/ssh/sign/:role}, which returns a <b>signed certificate</b>
 * for a presented public key. There is <b>no</b> {@code issue} method — Vault's
 * {@code /ssh/issue} (which mints and returns a private key) must never be
 * used, so the interface makes it structurally impossible (the CP never
 * receives an inner-leg private key). CI exercises this with a double; a
 * documented manual path binds the Vault HTTP client.
 */
public interface VaultSshEngine {

	record SignRequest(String keyId, List<String> validPrincipals, long ttlSeconds, Map<String, String> criticalOptions,
			List<String> extensions) {
	}

	record SignedCertificate(String certificateLine) {
	}

	String caPublicKeyLine();

	SignedCertificate sign(String role, String publicKeyOpenSshLine, SignRequest request);
}
