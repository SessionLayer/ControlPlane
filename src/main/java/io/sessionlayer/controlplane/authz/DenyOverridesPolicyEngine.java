package io.sessionlayer.controlplane.authz;

import io.sessionlayer.controlplane.data.config.DpRule;
import io.sessionlayer.controlplane.data.runtime.AccessLock;
import java.time.Instant;
import java.util.Collection;
import java.util.Comparator;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

/**
 * Hand-written deny-overrides evaluator. Avoids Cedar JNI; PolicyEngine seam
 * keeps Cedar swappable. Algebra: applicable rules → locks → denies →
 * default-deny → allow (login/capability unions per grant).
 * Commutative/idempotent; fail-closed.
 */
@Component
public class DenyOverridesPolicyEngine implements PolicyEngine {

	private static final Logger LOG = LoggerFactory.getLogger(DenyOverridesPolicyEngine.class);

	@Override
	public DataPlaneDecision evaluate(AuthorizationRequest request, Collection<DpRule> grants,
			Collection<AccessLock> locks, Instant now) {
		try {
			return decide(request, grants, locks, now);
		} catch (RuntimeException failClosed) {
			// Determinism is a security property; any error deterministically denies
			// (fail-closed).
			LOG.warn("data-plane evaluation failed closed: {}", failClosed.toString());
			return DataPlaneDecision.deny(DataPlaneDecision.Reason.EVALUATION_ERROR, null, null);
		}
	}

	private DataPlaneDecision decide(AuthorizationRequest request, Collection<DpRule> grants,
			Collection<AccessLock> locks, Instant now) {
		List<DpRule> applicable = grants.stream().filter(rule -> applies(rule, request))
				.sorted(Comparator.comparing(DpRule::id)).toList();
		List<DpRule> allows = applicable.stream().filter(DenyOverridesPolicyEngine::isAllow).toList();
		// Fail closed: anything that is not exactly an allow (a deny, or a mislabeled
		// effect the DB CHECK somehow let through) is treated as a deny.
		List<DpRule> denies = applicable.stream().filter(r -> !isAllow(r)).toList();

		Set<String> allowedLogins = new TreeSet<>();
		allows.forEach(r -> allowedLogins.addAll(principals(r)));

		AccessLock lock = matchingLock(request, allowedLogins, locks, now);
		if (lock != null) {
			return DataPlaneDecision.deny(DataPlaneDecision.Reason.LOCKED, lock.id(), lockName(lock));
		}
		if (!denies.isEmpty()) {
			DpRule d = denies.get(0);
			return DataPlaneDecision.deny(DataPlaneDecision.Reason.EXPLICIT_DENY, d.id(), d.name());
		}
		if (allows.isEmpty()) {
			return DataPlaneDecision.deny(DataPlaneDecision.Reason.NO_MATCHING_ALLOW, null, null);
		}

		String requested = request.requestedPrincipal();
		if (requested != null && !allowedLogins.contains(requested)) {
			return DataPlaneDecision.deny(DataPlaneDecision.Reason.PRINCIPAL_NOT_ALLOWED, null, null);
		}

		// Capabilities/TTL are gated per grant: scope them to the allows that grant
		// the CHOSEN login, so capabilities from a different login's grant never
		// bleed onto this connect. The null-principal ("what may I do") case keeps
		// the union across all allows.
		List<DpRule> contributing = requested == null
				? allows
				: allows.stream().filter(r -> principals(r).contains(requested)).toList();
		Set<String> capabilities = new TreeSet<>();
		contributing.forEach(r -> capabilities.addAll(Capabilities.effective(setOf(r.capabilities()))));
		// ttlSeconds is nullable now (a deny carries none), so filter BEFORE unboxing.
		// Every element here is an allow, which the write path still requires a TTL
		// for — but that is an invariant enforced in the database, and mapToInt on a
		// null would be an NPE on the decision path the first time it stopped holding.
		int grantTtl = contributing.stream().map(DpRule::ttlSeconds).filter(java.util.Objects::nonNull)
				.mapToInt(Integer::intValue).filter(t -> t > 0).min().orElse(0);
		DpRule representative = contributing.get(0); // applicable is id-sorted → lowest id
		return DataPlaneDecision.allow(allowedLogins, capabilities, grantTtl, representative.id(),
				representative.name());
	}

	private static boolean isAllow(DpRule rule) {
		return "allow".equals(rule.effect());
	}

	private static boolean applies(DpRule rule, AuthorizationRequest request) {
		if (!Selectors.identityMatches(rule.identitySelector(), request.identity(), request.groups())
				|| !Selectors.labelMatches(rule.nodeLabelSelector(), request.nodeLabels())) {
			return false;
		}
		// Source IP is DENY-ONLY: may suppress ALLOW but never removes DENY
		// (fail-closed).
		// Deny applies on identity ∧ node-label regardless of source.
		return !isAllow(rule) || Selectors.sourceIpPasses(rule.sourceIpCondition(), request.sourceIp());
	}

	private static AccessLock matchingLock(AuthorizationRequest request, Set<String> allowedLogins,
			Collection<AccessLock> locks, Instant now) {
		LockMatching.LockSubject subject = new LockMatching.LockSubject(request.identity(),
				request.nodeId() == null ? null : request.nodeId().toString(), request.nodeLabels(),
				Set.copyOf(allowedLogins), request.requestedPrincipal(), Set.copyOf(request.groups()));
		return locks.stream().filter(l -> unexpired(l, now))
				.filter(l -> LockMatching.matches(l.targetSelector(), subject))
				.min(Comparator.comparing(AccessLock::id)).orElse(null);
	}

	private static boolean unexpired(AccessLock lock, Instant now) {
		return lock.expiresAt() == null || lock.expiresAt().isAfter(now);
	}

	private static Set<String> principals(DpRule rule) {
		return setOf(rule.principals());
	}

	private static Set<String> setOf(List<String> values) {
		return values == null ? Set.of() : Set.copyOf(values);
	}

	private static String lockName(AccessLock lock) {
		return lock.reason() == null ? "lock" : "lock:" + lock.reason();
	}
}
