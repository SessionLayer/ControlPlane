package io.sessionlayer.controlplane.configapi;

import io.sessionlayer.controlplane.audit.AuditEventStore;
import io.sessionlayer.controlplane.data.config.DpRule;
import io.sessionlayer.controlplane.data.config.DpRuleRepository;
import io.sessionlayer.controlplane.web.ApiProblemException;
import io.sessionlayer.controlplane.web.CursorPages;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.dao.OptimisticLockingFailureException;
import org.springframework.data.relational.core.query.Criteria;
import org.springframework.stereotype.Service;
import org.springframework.transaction.reactive.TransactionalOperator;
import reactor.core.publisher.Mono;
import tools.jackson.databind.JsonNode;

@Service
public class RuleConfigService {

	private static final String ORIGIN_API = "api";
	private static final String EFFECT_ALLOW = "allow";

	private final DpRuleRepository rules;
	private final CursorPages cursorPages;
	private final AuditEventStore audit;
	private final TransactionalOperator tx;

	public RuleConfigService(DpRuleRepository rules, CursorPages cursorPages, AuditEventStore audit,
			TransactionalOperator tx) {
		this.rules = rules;
		this.cursorPages = cursorPages;
		this.audit = audit;
		this.tx = tx;
	}

	public Mono<CursorPages.Page<DpRule>> list(String cursor, Integer limit) {
		return cursorPages.page(DpRule.class, Criteria.empty(), cursor, limit, DpRule::id);
	}

	public Mono<DpRule> get(UUID id) {
		return rules.findById(id).switchIfEmpty(Mono.error(ApiProblemException.notFound("rule", id)));
	}

	public Mono<DpRule> create(String actor, String name, JsonNode identitySelector, JsonNode nodeLabelSelector,
			JsonNode sourceIpCondition, List<String> principals, Integer ttlSeconds, List<String> capabilities,
			String effect) {
		validate(ttlSeconds, effect, principals, identitySelector, nodeLabelSelector, sourceIpCondition);
		DpRule rule = DpRule.create(name, identitySelector, nodeLabelSelector, sourceIpCondition, principals,
				ttlSeconds, capabilities, effect, ORIGIN_API);
		return persist(null, rule, actor, "rule.create", name);
	}

	public Mono<DpRule> update(UUID id, String actor, Long expectedVersion, JsonNode identitySelector,
			JsonNode nodeLabelSelector, JsonNode sourceIpCondition, List<String> principals, Integer ttlSeconds,
			List<String> capabilities, String effect) {
		validate(ttlSeconds, effect, principals, identitySelector, nodeLabelSelector, sourceIpCondition);
		return get(id).flatMap(existing -> {
			requireVersion(expectedVersion, existing.version());
			DpRule updated = new DpRule(existing.id(), existing.name(), identitySelector, nodeLabelSelector,
					sourceIpCondition, principals, ttlSeconds, capabilities, effect, ORIGIN_API, existing.version(),
					existing.createdAt(), existing.updatedAt());
			return persist(existing, updated, actor, "rule.update", existing.name());
		});
	}

	public Mono<Void> delete(UUID id, String actor) {
		// Idempotent + auditable: capture the before-state, then delete + record the
		// change (before/after); a delete of a missing row is still audited.
		return rules.findById(id).flatMap(before -> deleteWithAudit(id, actor, before))
				.switchIfEmpty(Mono.defer(() -> deleteWithAudit(id, actor, null)));
	}

	private Mono<Void> deleteWithAudit(UUID id, String actor, DpRule before) {
		return tx.transactional(rules.deleteById(id)
				.then(audit.recordChange(actor, id.toString(), "rule.delete", Map.of(), before, null)));
	}

	private Mono<DpRule> persist(DpRule before, DpRule rule, String actor, String action, String name) {
		Mono<DpRule> body = rules.save(rule)
				.flatMap(saved -> audit
						.recordChange(actor, saved.id().toString(), action, Map.of("name", name), before, saved)
						.thenReturn(saved));
		return tx.transactional(body)
				.onErrorMap(OptimisticLockingFailureException.class,
						e -> ApiProblemException.conflict("the rule was modified concurrently (stale version)"))
				.onErrorMap(DataIntegrityViolationException.class,
						e -> ApiProblemException.conflict("a rule named '" + name + "' already exists"));
	}

	/**
	 * An allow's grant has a lifetime and must carry one; a deny grants nothing, so
	 * it has none to bound and may omit it. A value sent on a deny is STORED as
	 * given rather than nulled: "ignored" describes what the evaluator does with it
	 * — {@code DenyOverridesPolicyEngine} reads a TTL only from allows — and
	 * rewriting a caller's field on their behalf would change what a published
	 * endpoint echoes, and silently drop the value on the next update of any deny
	 * rule that already carries one.
	 */
	private static void validate(Integer ttlSeconds, String effect, List<String> principals, JsonNode identitySelector,
			JsonNode nodeLabelSelector, JsonNode sourceIpCondition) {
		if (EFFECT_ALLOW.equals(effect) && ttlSeconds == null) {
			// Named, because the failure this replaces was a framework 400 that named
			// nothing and left the operator guessing which field was wrong.
			throw ApiProblemException.validation("ttlSeconds is required when effect is 'allow'");
		}
		// Positivity is checked whenever a value is PRESENT, whatever the effect: the
		// column's CHECK (ttl_seconds > 0) still applies to a deny that carries one,
		// and reaching it would surface as an unmapped integrity failure rather than
		// as this 422.
		if (ttlSeconds != null && ttlSeconds <= 0) {
			throw ApiProblemException.validation("ttlSeconds must be > 0");
		}
		if (principals == null || principals.isEmpty()) {
			throw ApiProblemException.validation("principals must be non-empty");
		}
		// Reject a selector the evaluator can't parse pre-commit, so a malformed rule
		// never persists to fail-closed (or worse) on the decision path.
		SelectorValidation.identitySelector(identitySelector);
		SelectorValidation.labelSelector(nodeLabelSelector, "nodeLabelSelector");
		SelectorValidation.sourceIpCondition(sourceIpCondition);
	}

	private static void requireVersion(Long expected, Long actual) {
		if (expected != null && !expected.equals(actual)) {
			throw ApiProblemException.conflict("stale version " + expected + " (current " + actual + ")");
		}
	}
}
