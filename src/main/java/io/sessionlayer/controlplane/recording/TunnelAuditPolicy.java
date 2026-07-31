package io.sessionlayer.controlplane.recording;

import io.sessionlayer.controlplane.authz.Capabilities;
import java.util.Set;

public final class TunnelAuditPolicy {

	public static final int MAX_BATCH = 4096;

	public static final String UNKNOWN = "unknown";

	private static final int MAX_TARGET = 512;
	private static final Set<String> CAPABILITIES = Set.of(Capabilities.PORT_FORWARD_LOCAL,
			Capabilities.PORT_FORWARD_REMOTE, Capabilities.X11);
	private static final Set<String> DIRECTIONS = Set.of("local", "remote", "x11");

	private TunnelAuditPolicy() {
	}

	public static TunnelAuditEntry normalize(TunnelAuditEntry entry) {
		String capability = entry.capability() == null ? "" : entry.capability().trim();
		capability = CAPABILITIES.contains(capability) ? capability : UNKNOWN;
		String direction = DIRECTIONS.contains(entry.direction()) ? entry.direction() : UNKNOWN;
		String target = entry.target() == null ? "" : entry.target();
		if (target.length() > MAX_TARGET) {
			target = target.substring(0, MAX_TARGET);
		}
		return new TunnelAuditEntry(capability, direction, target, Math.max(0, entry.bytesIn()),
				Math.max(0, entry.bytesOut()), Math.max(0, entry.durationSeconds()));
	}

	public static String action(TunnelAuditEntry normalized) {
		return switch (normalized.capability()) {
			case Capabilities.X11 -> "x11_forward.closed";
			case Capabilities.PORT_FORWARD_LOCAL, Capabilities.PORT_FORWARD_REMOTE -> "port_forward.closed";
			default -> "tunnel.unknown";
		};
	}
}
