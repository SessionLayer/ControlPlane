package io.sessionlayer.controlplane.ha;

import io.sessionlayer.controlplane.data.runtime.Presence;
import java.time.Instant;
import org.springframework.stereotype.Component;

/**
 * The one "is this presence claim still live?" rule. Routing (the authorizer's
 * fresh-owner fold), the Gateway directory and the node API all answer from
 * {@code runtime.presence}, so they must agree on when a claim goes stale — a
 * second copy of the window would let the API call a node healthy that the
 * authorizer has already given up routing to.
 */
@Component
public class PresenceFreshness {

	private final HaProperties properties;

	public PresenceFreshness(HaProperties properties) {
		this.properties = properties;
	}

	public Instant staleBefore(Instant now) {
		return now.minus(properties.getPresenceStaleness());
	}

	public boolean isFresh(Presence presence, Instant now) {
		return presence != null && presence.lastSeen() != null && presence.lastSeen().isAfter(staleBefore(now));
	}
}
