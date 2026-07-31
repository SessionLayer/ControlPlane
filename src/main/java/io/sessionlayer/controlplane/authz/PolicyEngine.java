package io.sessionlayer.controlplane.authz;

import io.sessionlayer.controlplane.data.config.DpRule;
import io.sessionlayer.controlplane.data.runtime.AccessLock;
import java.time.Instant;
import java.util.Collection;

/**
 * Data-plane RBAC decision engine. Pure function of grant set: default-deny +
 * deny-overrides + order-independent + access_lock as top-tier deny. Kept
 * behind interface for Cedar swapping.
 */
public interface PolicyEngine {

	/**
	 * Evaluate request against grants and locks (order-independent; fail-closed on
	 * error).
	 *
	 * @param now
	 *            reference instant for lock expiry; passed for function purity
	 */
	DataPlaneDecision evaluate(AuthorizationRequest request, Collection<DpRule> grants, Collection<AccessLock> locks,
			Instant now);
}
