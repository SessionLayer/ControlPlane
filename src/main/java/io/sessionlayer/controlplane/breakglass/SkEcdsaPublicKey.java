package io.sessionlayer.controlplane.breakglass;

import io.sessionlayer.controlplane.ca.wire.SshReader;
import java.security.MessageDigest;
import java.util.Base64;

/**
 * Parses an OpenSSH sk-ecdsa-sha2-nistp256@openssh.com FIDO2 PUBLIC-key wire
 * blob and computes its OpenSSH SHA-256 fingerprint. The fingerprint
 * is "SHA256:" + base64-nopad(SHA-256(blob)) over the exact wire bytes. Fail
 * closed on malformed input.
 */
public final class SkEcdsaPublicKey {

	public static final String KEY_TYPE = "sk-ecdsa-sha2-nistp256@openssh.com";
	private static final String CURVE = "nistp256";
	private static final int P256_COORD_BYTES = 32;

	private SkEcdsaPublicKey() {
	}

	public record Parsed(String fingerprint, String application) {
	}

	public static Parsed parse(byte[] blob) {
		if (blob == null || blob.length == 0) {
			throw new IllegalArgumentException("empty sk-ecdsa blob");
		}
		SshReader reader = new SshReader(blob);
		String keyType = reader.readStringUtf8();
		if (!KEY_TYPE.equals(keyType)) {
			throw new IllegalArgumentException("not an sk-ecdsa-sha2-nistp256 key: " + keyType);
		}
		String curve = reader.readStringUtf8();
		if (!CURVE.equals(curve)) {
			throw new IllegalArgumentException("curve '" + curve + "' does not match " + KEY_TYPE);
		}
		byte[] q = reader.readString();
		if (q.length != 1 + 2 * P256_COORD_BYTES || q[0] != 0x04) {
			throw new IllegalArgumentException("expected uncompressed EC point (0x04||X||Y)");
		}
		String application = reader.readStringUtf8();
		if (reader.hasRemaining()) {
			throw new IllegalArgumentException("trailing bytes after sk-ecdsa application");
		}
		return new Parsed(fingerprint(blob), application);
	}

	public static String fingerprint(byte[] blob) {
		try {
			byte[] digest = MessageDigest.getInstance("SHA-256").digest(blob);
			return "SHA256:" + Base64.getEncoder().withoutPadding().encodeToString(digest);
		} catch (Exception e) {
			throw new IllegalStateException("SHA-256 unavailable", e);
		}
	}
}
