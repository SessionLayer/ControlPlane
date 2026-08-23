package io.sessionlayer.controlplane.grpc;

import static org.assertj.core.api.Assertions.assertThat;

import io.sessionlayer.controlplane.grpc.v1.ProtocolVersion;
import io.sessionlayer.controlplane.protocol.ProtocolVersions;
import java.util.Optional;
import org.junit.jupiter.api.Test;

class VersionNegotiatorTest {

	@Test
	void resolvesSinglePointBaseline() {
		assertThat(VersionNegotiator.highestCommon(v(1, 0), v(1, 0), v(1, 0), v(1, 0))).contains(v(1, 0));
	}

	@Test
	void picksHighestVersionWithinOverlap() {
		assertThat(VersionNegotiator.highestCommon(v(1, 0), v(1, 2), v(1, 1), v(1, 3))).contains(v(1, 2));
	}

	@Test
	void isOrderIndependent() {
		Optional<ProtocolVersion> a = VersionNegotiator.highestCommon(v(1, 0), v(1, 2), v(1, 1), v(1, 3));
		Optional<ProtocolVersion> b = VersionNegotiator.highestCommon(v(1, 1), v(1, 3), v(1, 0), v(1, 2));
		assertThat(a).isEqualTo(b).contains(v(1, 2));
	}

	@Test
	void comparesMinorWithinSameMajor() {
		assertThat(VersionNegotiator.highestCommon(v(1, 0), v(1, 5), v(1, 0), v(1, 4))).contains(v(1, 4));
	}

	@Test
	void failsClosedAcrossMajorGap() {
		assertThat(VersionNegotiator.highestCommon(v(2, 0), v(2, 0), v(1, 0), v(1, 0))).isEmpty();
	}

	@Test
	void failsClosedWhenClientEntirelyBelowServer() {
		assertThat(VersionNegotiator.highestCommon(v(1, 0), v(1, 0), v(1, 1), v(1, 2))).isEmpty();
	}

	@Test
	void currentVersionDisplaysAsOnePointOne() {
		assertThat(ProtocolVersions.display(ProtocolVersions.CURRENT)).isEqualTo("1.1");
		assertThat(ProtocolVersions.display(ProtocolVersions.SUPPORTED_MIN)).isEqualTo("1.0");
		assertThat(ProtocolVersions.display(ProtocolVersions.SUPPORTED_MAX)).isEqualTo("1.1");
	}

	private static ProtocolVersion v(int major, int minor) {
		return ProtocolVersions.of(major, minor);
	}
}
