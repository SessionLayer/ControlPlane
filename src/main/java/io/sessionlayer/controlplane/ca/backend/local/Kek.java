package io.sessionlayer.controlplane.ca.backend.local;

import java.security.SecureRandom;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public final class Kek {

	private static final int GCM_TAG_BITS = 128;
	private static final int IV_BYTES = 12;
	private static final SecureRandom RANDOM = new SecureRandom();

	private final byte[] keyBytes;

	public Kek(byte[] keyBytes) {
		if (keyBytes.length != 32) {
			throw new IllegalArgumentException("KEK must be 32 bytes (AES-256), got " + keyBytes.length);
		}
		this.keyBytes = keyBytes.clone();
	}

	public record Wrapped(byte[] iv, byte[] ciphertext) {
	}

	public Wrapped wrap(byte[] plaintext, byte[] aad) {
		try {
			byte[] iv = new byte[IV_BYTES];
			RANDOM.nextBytes(iv);
			Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
			cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(keyBytes, "AES"),
					new GCMParameterSpec(GCM_TAG_BITS, iv));
			cipher.updateAAD(aad);
			return new Wrapped(iv, cipher.doFinal(plaintext));
		} catch (Exception e) {
			throw new IllegalStateException("KEK wrap failed", e);
		}
	}

	/**
	 * Decrypt a wrapped blob, authenticating {@code aad}. Fails closed (throws) on
	 * any KEK / ciphertext / <b>context</b> mismatch. The caller MUST zeroize the
	 * returned plaintext after use.
	 */
	public byte[] unwrap(byte[] iv, byte[] ciphertext, byte[] aad) {
		try {
			Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
			cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(keyBytes, "AES"),
					new GCMParameterSpec(GCM_TAG_BITS, iv));
			cipher.updateAAD(aad);
			return cipher.doFinal(ciphertext);
		} catch (Exception e) {
			throw new IllegalStateException("KEK unwrap failed (wrong KEK, tampered ciphertext, or wrong CA context)",
					e);
		}
	}

	public void destroy() {
		Arrays.fill(keyBytes, (byte) 0);
	}
}
