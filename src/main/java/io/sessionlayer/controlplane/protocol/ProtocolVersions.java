package io.sessionlayer.controlplane.protocol;

import io.sessionlayer.controlplane.grpc.v1.ProtocolVersion;

public final class ProtocolVersions {

	public static final int MAJOR = 1;
	public static final int MINOR = 1;

	public static final ProtocolVersion CURRENT = of(MAJOR, MINOR);

	/**
	 * Inclusive lowest supported version — held at the previous minor (1.0) to
	 * honour the N-1 window (VERSIONING.md §4): a 1.1 CP still negotiates 1.0 with
	 * a peer that has not upgraded.
	 */
	public static final ProtocolVersion SUPPORTED_MIN = of(MAJOR, MINOR - 1);

	public static final ProtocolVersion SUPPORTED_MAX = CURRENT;

	private ProtocolVersions() {
	}

	public static ProtocolVersion of(int major, int minor) {
		return ProtocolVersion.newBuilder().setMajor(major).setMinor(minor).build();
	}

	public static String display(ProtocolVersion version) {
		return Integer.toUnsignedString(version.getMajor()) + "." + Integer.toUnsignedString(version.getMinor());
	}
}
