package io.sessionlayer.controlplane.grpc;

import io.sessionlayer.controlplane.grpc.v1.ProtocolVersion;
import java.util.Optional;

public final class VersionNegotiator {

	private VersionNegotiator() {
	}

	public static Optional<ProtocolVersion> highestCommon(ProtocolVersion clientMin, ProtocolVersion clientMax,
			ProtocolVersion serverMin, ProtocolVersion serverMax) {
		ProtocolVersion low = higher(clientMin, serverMin);
		ProtocolVersion high = lower(clientMax, serverMax);
		return compare(low, high) <= 0 ? Optional.of(high) : Optional.empty();
	}

	public static int compare(ProtocolVersion a, ProtocolVersion b) {
		int byMajor = Integer.compareUnsigned(a.getMajor(), b.getMajor());
		return byMajor != 0 ? byMajor : Integer.compareUnsigned(a.getMinor(), b.getMinor());
	}

	private static ProtocolVersion higher(ProtocolVersion a, ProtocolVersion b) {
		return compare(a, b) >= 0 ? a : b;
	}

	private static ProtocolVersion lower(ProtocolVersion a, ProtocolVersion b) {
		return compare(a, b) <= 0 ? a : b;
	}
}
