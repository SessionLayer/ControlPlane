package io.sessionlayer.controlplane.authz;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class AuditSourceIpTest {

	@ParameterizedTest
	@ValueSource(strings = {"10.0.0.5", "0.0.0.0", "255.255.255.255", "127.0.0.1", "192.168.1.1", "::1", "2001:db8::1",
			"fe80::1", "::"})
	void acceptsCanonicalLiterals(String value) {
		assertThat(AuditSourceIp.isCanonicalLiteral(value)).as(value).isTrue();
	}

	@ParameterizedTest
	@ValueSource(strings = {"16909060", "1.2.3", "127.1", "010.0.0.1", "256.0.0.1", "1.2.3.4.5", "1.2.3.", "10.0.0.05",
			"999.1.1.1", "dead.beef", "abc", "cafe", "example.com", "", "   ", "10.0.0.-1"})
	void rejectsNonInetAndAbbreviatedForms(String value) {
		assertThat(AuditSourceIp.isCanonicalLiteral(value)).as(value).isFalse();
	}

	@Test
	void rejectsNull() {
		assertThat(AuditSourceIp.isCanonicalLiteral(null)).isFalse();
	}

	@Test
	void trimsSurroundingWhitespaceForOtherwiseValidLiterals() {
		assertThat(AuditSourceIp.isCanonicalLiteral("  10.0.0.5  ")).isTrue();
	}
}
