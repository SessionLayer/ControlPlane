package io.sessionlayer.controlplane.security;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

/**
 * The gate denies a CIDR it cannot parse instead of raising, which is correct
 * at request time and leaves a typo indistinguishable from a correct non-match.
 * Boot is where that has to become legible again.
 *
 * <p>
 * {@code ::1/300} is the case that proves the validator probes both address
 * families: a v4-only probe short-circuits on the family mismatch before the
 * prefix range check, so it would call that entry usable and leave it failing
 * at every request instead — the defect this check exists to remove,
 * reintroduced inside the check itself.
 */
class BasicEscapeHatchCidrValidationTest {

	@ParameterizedTest
	@ValueSource(strings = {"127.0.0.1", "10.0.0.0/99", "::1/300", "not-a-cidr/8", "10.0.0.0/-1"})
	void anUnusableCidrRefusesToStartAndNamesItself(String cidr) {
		assertThatThrownBy(() -> enabled(cidr).validateIfEnabled()).isInstanceOf(IllegalStateException.class)
				.hasMessageContaining(cidr);
	}

	/**
	 * The whole point is that the operator learns WHICH line is wrong without
	 * reading code. Asserting only that the bad entry appears is not enough: the
	 * underlying parse failure echoes it too, so a message naming the wrong entry
	 * still contains it. The good entries must be absent.
	 */
	@Test
	void oneBadEntryAmongGoodOnesIsTheOneNamed() {
		assertThatThrownBy(() -> enabled("127.0.0.1/32", "10.0.0.0", "::1/128").validateIfEnabled())
				.isInstanceOf(IllegalStateException.class).hasMessageContaining("10.0.0.0")
				.hasMessageNotContaining("127.0.0.1/32").hasMessageNotContaining("::1/128");
	}

	@Test
	void aBlankEntryRefusesToStart() {
		assertThatThrownBy(() -> enabled("").validateIfEnabled()).isInstanceOf(IllegalStateException.class);
	}

	@Test
	void anEnabledHatchWithNoCidrsRefusesToStart() {
		assertThatThrownBy(() -> enabled().validateIfEnabled()).isInstanceOf(IllegalStateException.class);
	}

	/**
	 * A stale entry under a disabled hatch must not take the Control Plane down
	 * over a feature nobody asked for. This is the case a later simplification
	 * would drop, and dropping it turns an opt-in feature into a boot dependency.
	 */
	@ParameterizedTest
	@ValueSource(strings = {"127.0.0.1", "not-a-cidr/8", "::1/300"})
	void aDisabledHatchStartsWhateverItsCidrsSay(String cidr) {
		SecurityProperties.BasicAuth disabled = enabled(cidr);
		disabled.setEnabled(false);

		assertThatCode(() -> disabled.validateIfEnabled()).doesNotThrowAnyException();
	}

	@ParameterizedTest
	@ValueSource(strings = {"127.0.0.1/32", "10.0.0.0/8", "::1/128", "fe80::/10"})
	void aUsableCidrStarts(String cidr) {
		assertThatCode(() -> enabled(cidr).validateIfEnabled()).doesNotThrowAnyException();
	}

	private static SecurityProperties.BasicAuth enabled(String... allowedCidrs) {
		SecurityProperties.BasicAuth config = new SecurityProperties.BasicAuth();
		config.setEnabled(true);
		config.setAllowedCidrs(List.of(allowedCidrs));
		return config;
	}
}
