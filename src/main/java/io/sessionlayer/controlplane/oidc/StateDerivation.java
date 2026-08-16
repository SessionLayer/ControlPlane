package io.sessionlayer.controlplane.oidc;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.springframework.stereotype.Component;

@Component
public class StateDerivation {

	private static final org.slf4j.Logger LOG = org.slf4j.LoggerFactory.getLogger(StateDerivation.class);

	private final byte[] key;

	public StateDerivation(OidcProperties properties) {
		String configured = properties.getStateHmacKey();
		if (configured != null && !configured.isBlank()) {
			this.key = java.util.Base64.getDecoder().decode(configured.trim());
		} else {
			this.key = new byte[32];
			new SecureRandom().nextBytes(this.key);
			LOG.info("OIDC state-derivation key is per-boot (single instance). Set sessionlayer.oidc.state-hmac-key "
					+ "to a shared value for HA (else a login begun on one instance cannot complete on another).");
		}
	}

	public String verifier(String state) {
		return base64Url(hmac(state + ":pkce"));
	}

	public String nonce(String state) {
		return base64Url(hmac(state + ":nonce"));
	}

	public String challenge(String state) {
		try {
			byte[] digest = MessageDigest.getInstance("SHA-256")
					.digest(verifier(state).getBytes(StandardCharsets.UTF_8));
			return base64Url(digest);
		} catch (Exception e) {
			throw new IllegalStateException("SHA-256 unavailable", e);
		}
	}

	private byte[] hmac(String message) {
		try {
			Mac mac = Mac.getInstance("HmacSHA256");
			mac.init(new SecretKeySpec(key, "HmacSHA256"));
			return mac.doFinal(message.getBytes(StandardCharsets.UTF_8));
		} catch (Exception e) {
			throw new IllegalStateException("HMAC unavailable", e);
		}
	}

	private static String base64Url(byte[] raw) {
		return Base64.getUrlEncoder().withoutPadding().encodeToString(raw);
	}
}
