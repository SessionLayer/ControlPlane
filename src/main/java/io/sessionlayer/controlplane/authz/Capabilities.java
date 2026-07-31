package io.sessionlayer.controlplane.authz;

import java.util.Set;

public final class Capabilities {

	public static final String SHELL = "shell";
	public static final String EXEC = "exec";
	public static final String SFTP = "sftp";
	public static final String SCP = "scp";
	public static final String PORT_FORWARD_LOCAL = "port_forward_local";
	public static final String PORT_FORWARD_REMOTE = "port_forward_remote";
	public static final String AGENT_FORWARD = "agent_forward";
	public static final String X11 = "x11";

	public static final Set<String> ALL = Set.of(SHELL, EXEC, SFTP, SCP, PORT_FORWARD_LOCAL, PORT_FORWARD_REMOTE,
			AGENT_FORWARD, X11);

	public static final Set<String> DEFAULT = Set.of(SHELL, EXEC);

	private Capabilities() {
	}

	public static Set<String> effective(Set<String> granted) {
		return (granted == null || granted.isEmpty()) ? DEFAULT : Set.copyOf(granted);
	}
}
