package io.sessionlayer.controlplane.platform;

import java.util.Set;

public final class PlatformPermissions {

	public static final String RBAC_READ = "rbac:read";
	public static final String RBAC_WRITE = "rbac:write";
	public static final String NODE_ENROLL = "node:enroll";
	public static final String GATEWAY_ENROLL = "gateway:enroll";
	public static final String GATEWAY_REMOVE = "gateway:remove";
	public static final String NODE_QUARANTINE = "node:quarantine";
	public static final String NODE_REMOVE = "node:remove";
	public static final String CA_MANAGE = "ca:manage";
	public static final String CA_ROTATE = "ca:rotate";
	public static final String REQUEST_APPROVE = "request:approve";
	public static final String RECORDING_REPLAY = "recording:replay";
	public static final String RECORDING_EXPORT = "recording:export";
	public static final String RECORDING_DELETE = "recording:delete";
	public static final String RECORDING_KEY_MANAGE = "recording:key-manage";
	public static final String AUDIT_READ = "audit:read";
	public static final String METRICS_READ = "metrics:read";
	public static final String USER_MANAGE = "user:manage";
	public static final String SETTINGS_WRITE = "settings:write";
	public static final String LOCK_READ = "lock:read";
	public static final String LOCK_WRITE = "lock:write";
	public static final String BREAKGLASS_MANAGE = "breakglass:manage";

	public static final Set<String> ALL = Set.of(RBAC_READ, RBAC_WRITE, NODE_ENROLL, GATEWAY_ENROLL, GATEWAY_REMOVE,
			NODE_QUARANTINE, NODE_REMOVE, CA_MANAGE, CA_ROTATE, REQUEST_APPROVE, RECORDING_REPLAY, RECORDING_EXPORT,
			RECORDING_DELETE, RECORDING_KEY_MANAGE, AUDIT_READ, METRICS_READ, USER_MANAGE, SETTINGS_WRITE, LOCK_READ,
			LOCK_WRITE, BREAKGLASS_MANAGE);

	/**
	 * {@link #METRICS_READ} is deliberately absent. The meter set is a fleet-wide
	 * aggregate with no per-node or per-user dimension to narrow, so a scope could
	 * only be a no-op or serve a silently PARTIAL meter set - and a scraper that
	 * receives incomplete metrics without knowing it builds confident wrong
	 * dashboards, which is worse than the clean 403 it gets without the permission.
	 */
	public static final Set<String> SCOPABLE = Set.of(RECORDING_REPLAY, RECORDING_EXPORT, AUDIT_READ);

	private PlatformPermissions() {
	}
}
