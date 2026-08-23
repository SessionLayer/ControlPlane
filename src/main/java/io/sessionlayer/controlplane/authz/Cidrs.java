package io.sessionlayer.controlplane.authz;

import java.net.InetAddress;

public final class Cidrs {

	private Cidrs() {
	}

	public static boolean contains(String cidr, String ip) {
		int slash = cidr.indexOf('/');
		if (slash < 0) {
			throw new IllegalArgumentException("not a CIDR (missing prefix): " + cidr);
		}
		byte[] network = address(cidr.substring(0, slash));
		int prefix = Integer.parseInt(cidr.substring(slash + 1).trim());
		byte[] candidate = address(ip);
		if (network.length != candidate.length) {
			return false; // different address family
		}
		if (prefix < 0 || prefix > network.length * 8) {
			throw new IllegalArgumentException("prefix out of range: " + cidr);
		}
		int fullBytes = prefix / 8;
		int remBits = prefix % 8;
		for (int i = 0; i < fullBytes; i++) {
			if (network[i] != candidate[i]) {
				return false;
			}
		}
		if (remBits == 0) {
			return true;
		}
		int mask = 0xFF << (8 - remBits) & 0xFF;
		return (network[fullBytes] & mask) == (candidate[fullBytes] & mask);
	}

	private static byte[] address(String literal) {
		String trimmed = literal.trim();
		// Reject hostnames explicitly: only numeric literals are valid here, so a
		// value that is not a literal must fail closed. InetAddress.ofLiteral parses an
		// IP literal WITHOUT any name lookup (JDK 22+) - unlike getByName, which would
		// do a BLOCKING DNS resolution for a non-literal on the reactive event loop.
		if (!isNumericLiteral(trimmed)) {
			throw new IllegalArgumentException("not a numeric IP literal: " + literal);
		}
		try {
			return InetAddress.ofLiteral(trimmed).getAddress();
		} catch (RuntimeException malformed) {
			throw new IllegalArgumentException("malformed IP literal: " + literal, malformed);
		}
	}

	private static boolean isNumericLiteral(String value) {
		if (value.isEmpty()) {
			return false;
		}
		for (int i = 0; i < value.length(); i++) {
			char c = value.charAt(i);
			boolean allowed = c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F' || c == '.'
					|| c == ':';
			if (!allowed) {
				return false;
			}
		}
		return true;
	}

	public static boolean isAddress(String ip) {
		try {
			address(ip);
			return true;
		} catch (RuntimeException notAnAddress) {
			return false;
		}
	}
}
