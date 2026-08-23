package io.sessionlayer.controlplane.platform;

import java.util.List;

public record PlatformSubject(String identity, List<String> groups) {

	public PlatformSubject {
		groups = (groups == null) ? List.of() : List.copyOf(groups);
	}
}
