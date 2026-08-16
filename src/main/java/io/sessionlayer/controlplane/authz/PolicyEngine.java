package io.sessionlayer.controlplane.authz;

import io.sessionlayer.controlplane.data.config.DpRule;
import io.sessionlayer.controlplane.data.runtime.AccessLock;
import java.time.Instant;
import java.util.Collection;

public interface PolicyEngine {

	DataPlaneDecision evaluate(AuthorizationRequest request, Collection<DpRule> grants, Collection<AccessLock> locks,
			Instant now);
}
