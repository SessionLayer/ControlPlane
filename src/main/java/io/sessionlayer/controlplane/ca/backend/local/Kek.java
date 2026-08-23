package io.sessionlayer.controlplane.ca.backend.local;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.Mac;
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

	/**
	 * HKDF-SHA256 (RFC 5869) a subkey for a purpose other than wrapping. The KEK is
	 * the one secret every Control Plane replica already shares, which makes it the
	 * only thing a second replica can derive an identical key from without
	 * coordination - but a key used for two purposes is a key whose compromise
	 * costs twice, so callers get a separated subkey, never these bytes.
	 */
	public byte[] derive(String info, int lengthBytes) {
		if (lengthBytes < 1 || lengthBytes > 255 * 32) {
			throw new IllegalArgumentException("HKDF output length out of range: " + lengthBytes);
		}
		try {
			Mac mac = Mac.getInstance("HmacSHA256");
			mac.init(new SecretKeySpec(new byte[32], "HmacSHA256"));
			byte[] prk = mac.doFinal(keyBytes);

			byte[] infoBytes = info.getBytes(StandardCharsets.UTF_8);
			byte[] out = new byte[lengthBytes];
			byte[] block = new byte[0];
			mac.init(new SecretKeySpec(prk, "HmacSHA256"));
			for (int written = 0, counter = 1; written < lengthBytes; counter++) {
				mac.update(block);
				mac.update(infoBytes);
				mac.update((byte) counter);
				block = mac.doFinal();
				int take = Math.min(block.length, lengthBytes - written);
				System.arraycopy(block, 0, out, written, take);
				written += take;
			}
			Arrays.fill(prk, (byte) 0);
			return out;
		} catch (Exception e) {
			throw new IllegalStateException("KEK subkey derivation failed", e);
		}
	}

	public void destroy() {
		Arrays.fill(keyBytes, (byte) 0);
	}
}
