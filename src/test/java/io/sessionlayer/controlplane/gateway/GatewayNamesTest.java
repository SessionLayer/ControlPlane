package io.sessionlayer.controlplane.gateway;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.Arrays;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class GatewayNamesTest {

	private static final List<String> CP_HOSTNAMES = List.of("localhost", "controlplane");

	@Test
	void wellFormedNamesAreValid() {
		assertThat(GatewayNames.isValid("gw-1")).isTrue();
		assertThat(GatewayNames.isValid("gw.edge.example.com")).isTrue();
	}

	@ParameterizedTest
	@ValueSource(strings = {"bad name!", "gw/../etc", "gw\nname", "gw:22", ""})
	void malformedNamesAreRejected(String name) {
		assertThat(GatewayNames.isValid(name)).isFalse();
		assertThat(GatewayNames.isEnrollable(name, CP_HOSTNAMES)).isFalse();
	}

	@Test
	void aNullNameIsRejected() {
		assertThat(GatewayNames.isValid(null)).isFalse();
	}

	/**
	 * The name becomes the CN and dNSName SAN of a serverAuth leaf, so a Gateway
	 * named after the Control Plane would be accepted AS the Control Plane by any
	 * peer pinning the internal mTLS CA.
	 */
	@ParameterizedTest
	@ValueSource(strings = {"controlplane", "localhost"})
	void theControlPlanesOwnHostnamesAreNotEnrollable(String hostname) {
		assertThat(GatewayNames.isValid(hostname)).as("shape check alone still admits it").isTrue();
		assertThat(GatewayNames.isEnrollable(hostname, CP_HOSTNAMES)).isFalse();
	}

	@ParameterizedTest
	@ValueSource(strings = {"CONTROLPLANE", "ControlPlane", "controlplane.", "controlplane...", "CONTROLPLANE."})
	void theReservedCheckFoldsCaseAndTheTrailingRootDot(String evasion) {
		assertThat(GatewayNames.isEnrollable(evasion, CP_HOSTNAMES))
				.as("DNS matching treats %s as the CP's own name", evasion).isFalse();
	}

	@Test
	void anOrdinaryGatewayNameStaysEnrollable() {
		assertThat(GatewayNames.isEnrollable("gw-edge-1", CP_HOSTNAMES)).isTrue();
		assertThat(GatewayNames.isEnrollable("controlplane-gw", CP_HOSTNAMES))
				.as("only an exact hostname match is reserved, not a prefix").isTrue();
	}

	@Test
	void absentOrNullHostnameEntriesAreTolerated() {
		assertThat(GatewayNames.isEnrollable("gw-1", null)).isTrue();
		assertThat(GatewayNames.isEnrollable("gw-1", Arrays.asList("localhost", null))).isTrue();
		assertThat(GatewayNames.isEnrollable("localhost", Arrays.asList("localhost", null))).isFalse();
	}
}
