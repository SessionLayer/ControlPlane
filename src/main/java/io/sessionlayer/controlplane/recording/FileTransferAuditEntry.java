package io.sessionlayer.controlplane.recording;

public record FileTransferAuditEntry(String operation, String path, String direction, long size, String sha256) {
}
