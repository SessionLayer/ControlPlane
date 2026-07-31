package io.sessionlayer.controlplane.recording;

public record TunnelAuditEntry(String capability, String direction, String target, long bytesIn, long bytesOut,
		long durationSeconds) {
}
