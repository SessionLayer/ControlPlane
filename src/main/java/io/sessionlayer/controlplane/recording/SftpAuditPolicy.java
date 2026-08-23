package io.sessionlayer.controlplane.recording;

import java.util.Locale;
import java.util.Set;
import java.util.regex.Pattern;

public final class SftpAuditPolicy {

	public static final int MAX_BATCH = 4096;

	private static final int MAX_PATH = 4096;
	private static final Pattern SHA256 = Pattern.compile("^sha256:[0-9a-f]{64}$");
	private static final Set<String> OPERATIONS = Set.of("open", "opendir", "read", "write", "close", "rename",
			"remove", "mkdir", "rmdir", "setstat", "fsetstat", "realpath", "stat", "lstat", "readdir", "symlink", "put",
			"get");

	private SftpAuditPolicy() {
	}

	public static FileTransferAuditEntry normalize(FileTransferAuditEntry entry) {
		String operation = entry.operation() == null ? "" : entry.operation().trim().toLowerCase(Locale.ROOT);
		operation = OPERATIONS.contains(operation) ? operation : "unknown";
		String direction = "upload".equals(entry.direction()) || "download".equals(entry.direction())
				? entry.direction()
				: "unknown";
		String path = entry.path() == null ? "" : entry.path();
		if (path.length() > MAX_PATH) {
			path = path.substring(0, MAX_PATH);
		}
		long size = Math.max(0, entry.size());
		String sha256 = entry.sha256() != null && SHA256.matcher(entry.sha256().trim()).matches()
				? entry.sha256().trim()
				: null;
		return new FileTransferAuditEntry(operation, path, direction, size, sha256);
	}
}
