package io.sessionlayer.controlplane.gateway;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.HexFormat;

public final class SingleUseTokens {

	private static final SecureRandom RANDOM = new SecureRandom();
	private static final int TOKEN_BYTES = 32;

	private SingleUseTokens() {
	}

	public record Minted(String raw, String hash) {
	}

	public static Minted mint() {
		byte[] material = new byte[TOKEN_BYTES];
		RANDOM.nextBytes(material);
		String raw = Base64.getUrlEncoder().withoutPadding().encodeToString(material);
		return new Minted(raw, hash(raw));
	}

	public static String hash(String rawToken) {
		try {
			byte[] digest = MessageDigest.getInstance("SHA-256").digest(rawToken.getBytes(StandardCharsets.UTF_8));
			return HexFormat.of().formatHex(digest);
		} catch (Exception e) {
			throw new IllegalStateException("SHA-256 unavailable", e);
		}
	}
}
