package io.sessionlayer.controlplane.authz;

import com.google.re2j.Pattern;

/**
 * Anchored RE2/J label operator - no backtracking, so ReDoS-safe.
 */
public final class AnchoredRe2 {

	static final int MAX_PATTERN_LENGTH = 1024;
	static final int MAX_INPUT_LENGTH = 4096;

	private AnchoredRe2() {
	}

	public static boolean matches(String regex, String value) {
		if (regex == null || value == null) {
			return false;
		}
		if (regex.length() > MAX_PATTERN_LENGTH) {
			throw new IllegalArgumentException("label regex exceeds max length");
		}
		if (value.length() > MAX_INPUT_LENGTH) {
			return false; // an over-long label value simply cannot be a valid match
		}
		return Pattern.matches(regex, value);
	}
}
