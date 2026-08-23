package io.sessionlayer.controlplane.agent;

import java.util.regex.Pattern;

public final class AgentNodeNames {

	private static final int MAX_LENGTH = 253;

	private static final Pattern LABEL = Pattern.compile("^[A-Za-z0-9_]([A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?$");

	private AgentNodeNames() {
	}

	public static boolean isValid(String nodeName) {
		if (nodeName == null || nodeName.isEmpty() || nodeName.length() > MAX_LENGTH) {
			return false;
		}
		for (String label : nodeName.split("\\.", -1)) {
			if (!LABEL.matcher(label).matches()) {
				return false;
			}
		}
		return true;
	}
}
