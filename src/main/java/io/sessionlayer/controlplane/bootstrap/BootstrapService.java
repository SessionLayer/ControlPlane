package io.sessionlayer.controlplane.bootstrap;

import io.sessionlayer.controlplane.audit.AuditEventStore;
import io.sessionlayer.controlplane.auth.Secrets;
import io.sessionlayer.controlplane.authz.SessionLimitProperties;
import io.sessionlayer.controlplane.data.config.OperatorSettings;
import io.sessionlayer.controlplane.data.config.OperatorSettingsRepository;
import io.sessionlayer.controlplane.data.config.PlatformRole;
import io.sessionlayer.controlplane.data.config.PlatformRoleRepository;
import io.sessionlayer.controlplane.data.config.RoleBinding;
import io.sessionlayer.controlplane.data.config.RoleBindingRepository;
import io.sessionlayer.controlplane.platform.PlatformPermissions;
import java.util.List;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.OptimisticLockingFailureException;
import org.springframework.r2dbc.core.DatabaseClient;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

/**
 * First-admin bootstrap (Design §2A, FR-BOOT-2). On an unconfigured system it
 * provisions the initial platform admin — a config-named OIDC subject, or a
 * printed-once credential surrendered via {@code POST /v1/bootstrap/claim} —
 * seeding a {@code platform-admin} role + a {@code role_binding}. It
 * <b>self-disables</b> once a platform admin with {@code user:manage} +
 * {@code rbac:write} exists (a race-safe conditional flip of
 * {@code operator_settings.bootstrap_completed}), and every use is audited.
 */
@Service
public class BootstrapService {

	private static final Logger LOG = LoggerFactory.getLogger(BootstrapService.class);
	private static final String ADMIN_ROLE = "platform-admin";

	// Race-safe self-disable: only the caller that flips completed=false→true wins
	// and provisions; concurrent HA callers observe zero rows and stand down.
	private static final String CLAIM_COMPLETION = """
			UPDATE config.operator_settings
			SET bootstrap_completed = true, bootstrap_completed_at = now(), version = version + 1
			WHERE singleton = true AND bootstrap_completed = false
			RETURNING id""";

	private final OperatorSettingsRepository settings;
	private final PlatformRoleRepository roles;
	private final RoleBindingRepository bindings;
	private final BootstrapProperties properties;
	private final SessionLimitProperties sessionLimits;
	private final AuditEventStore audit;
	private final DatabaseClient db;

	public BootstrapService(OperatorSettingsRepository settings, PlatformRoleRepository roles,
			RoleBindingRepository bindings, BootstrapProperties properties, SessionLimitProperties sessionLimits,
			AuditEventStore audit, DatabaseClient db) {
		this.settings = settings;
		this.roles = roles;
		this.bindings = bindings;
		this.properties = properties;
		this.sessionLimits = sessionLimits;
		this.audit = audit;
		this.db = db;
	}

	public enum ClaimOutcome {
		PROVISIONED, ALREADY_COMPLETED, INVALID_CREDENTIAL, NOT_CREDENTIAL_MODE
	}

	public Mono<Void> runAtStartup() {
		return ensureSettings().flatMap(current -> hasPlatformAdmin().flatMap(adminExists -> {
			if (current.bootstrapCompleted()) {
				return Mono.empty();
			}
			if (adminExists) {
				LOG.info("first-admin bootstrap: a platform admin already exists — self-disabling");
				return completeBootstrap().then();
			}
			if (properties.getAdminSubject() != null && !properties.getAdminSubject().isBlank()) {
				return provisionAndComplete(properties.getAdminSubject(), properties.getAdminSubjectKind(),
						"config_named_subject").then();
			}
			return armPrintedCredential(current).then();
		})).then(warnWhenSeededAdminVocabularyIsStale());
	}

	/**
	 * Detects — never mutates — the upgrade defect V29 back-filled.
	 * {@link #ensureAdminRole()} is create-only and this method's caller returns
	 * early once bootstrap has completed, so a vocabulary-extending migration that
	 * forgets to back-fill leaves the seeded admin role silently short of the new
	 * permission, and the only symptom is a 403 on an operation the admin should be
	 * able to perform. Scoped to the untouched seeded row: a role an operator has
	 * curated through {@code /v1/roles} may be deliberately narrower, and warning
	 * about that on every boot would be noise. Detection rather than mutation,
	 * precisely so it can never fight an operator's deliberate choice.
	 */
	private Mono<Void> warnWhenSeededAdminVocabularyIsStale() {
		return roles.findByName(ADMIN_ROLE).doOnNext(role -> {
			if (!"default".equals(role.origin())) {
				return;
			}
			List<String> held = role.permissions() == null ? List.of() : role.permissions();
			List<String> missing = PlatformPermissions.ALL.stream().filter(p -> !held.contains(p)).sorted().toList();
			if (!missing.isEmpty()) {
				LOG.warn("the seeded '{}' role is missing {} of the platform permissions: {}. It was created before "
						+ "those verbs existed and is never rewritten, so every operation they gate is refused. "
						+ "Grant them with PUT /v1/roles/{{id}}.", ADMIN_ROLE, missing.size(), missing);
			}
		}).then();
	}

	/** Claim the printed-once credential to become the first admin (FR-BOOT-2). */
	public Mono<ClaimOutcome> claim(String credential, String subject) {
		if (subject == null || subject.isBlank() || credential == null || credential.isBlank()) {
			return Mono.just(ClaimOutcome.INVALID_CREDENTIAL);
		}
		return settings.findSingleton().flatMap(current -> {
			if (current.bootstrapCompleted()) {
				return Mono.just(ClaimOutcome.ALREADY_COMPLETED);
			}
			if (current.bootstrapCredentialHash() == null) {
				return Mono.just(ClaimOutcome.NOT_CREDENTIAL_MODE);
			}
			if (!Secrets.constantTimeEquals(Secrets.sha256Hex(credential), current.bootstrapCredentialHash())) {
				return audit.record(subject, subject, "bootstrap.claim", "denied", null, null,
						Map.of("reason", "invalid_credential")).thenReturn(ClaimOutcome.INVALID_CREDENTIAL);
			}
			// Flip first (single winner), then provision — a lost race never
			// double-provisions.
			return db.sql(CLAIM_COMPLETION).map(row -> row.get("id")).one()
					.flatMap(won -> provisionAdminRole(subject, "user", "printed_credential")
							.thenReturn(ClaimOutcome.PROVISIONED))
					.switchIfEmpty(Mono.just(ClaimOutcome.ALREADY_COMPLETED));
		}).defaultIfEmpty(ClaimOutcome.NOT_CREDENTIAL_MODE);
	}

	private Mono<Void> provisionAndComplete(String subject, String subjectKind, String via) {
		return db.sql(CLAIM_COMPLETION).map(row -> row.get("id")).one()
				.flatMap(won -> provisionAdminRole(subject, subjectKind, via)).then();
	}

	private Mono<Void> provisionAdminRole(String subject, String subjectKind, String via) {
		return ensureAdminRole().flatMap(role -> ensureBinding(role, subject, subjectKind))
				.flatMap(binding -> audit.record(subject, subject, "bootstrap.provision", "success", null, null,
						Map.of("via", via, "role", ADMIN_ROLE, "subject_kind", subjectKind)))
				.doOnSuccess(
						v -> LOG.info("first-admin bootstrap: provisioned platform admin {} (via {})", subject, via))
				.then();
	}

	private Mono<PlatformRole> ensureAdminRole() {
		return roles.findByName(ADMIN_ROLE).switchIfEmpty(
				Mono.defer(() -> roles.save(PlatformRole.create(ADMIN_ROLE, List.copyOf(PlatformPermissions.ALL),
						"First-admin bootstrap role" + " (all platform permissions).", "default"))));
	}

	private Mono<RoleBinding> ensureBinding(PlatformRole role, String subject, String subjectKind) {
		return bindings.findByRoleId(role.id())
				.filter(b -> subjectKind.equals(b.subjectKind()) && subject.equals(b.subject())).next()
				.switchIfEmpty(Mono.defer(
						() -> bindings.save(RoleBinding.create(role.id(), subjectKind, subject, null, "default"))));
	}

	private Mono<Void> armPrintedCredential(OperatorSettings current) {
		if (current.bootstrapCredentialHash() != null) {
			LOG.info("first-admin bootstrap: a printed credential is already armed; awaiting claim");
			return Mono.empty();
		}
		String credential = Secrets.randomToken(24);
		OperatorSettings armed = withCredentialHash(current, Secrets.sha256Hex(credential));
		// The `subject` becomes a role_binding matched against the authenticated
		// identity, so naming only an OIDC subject would strand an operator installing
		// without an IdP: their only other first credential is the Basic escape hatch,
		// whose username must be the value claimed here.
		return settings.save(armed).doOnSuccess(s -> LOG
				.warn("FIRST-ADMIN BOOTSTRAP CREDENTIAL (shown once): {}  — claim it via POST /v1/bootstrap/claim "
						+ "{{\"credential\":\"...\",\"subject\":\"<subject>\"}}; it self-disables after use. "
						+ "The subject MUST be exactly the identity you will authenticate as: your OIDC subject "
						+ "when an IdP is configured, or the value of sessionlayer.rest-security.basic-auth.username "
						+ "when you are using the HTTP Basic escape hatch. A mismatch claims the bootstrap "
						+ "successfully and then refuses every authenticated call.", credential))
				// Stand down, deliberately NOT the retry its neighbour above uses. Losing
				// this race means a sibling replica armed first and has ALREADY printed
				// its credential, which is the only copy in existence — only the hash is
				// stored. Re-arming would invalidate a value the operator may already
				// have copied and leave two printed credentials in aggregated logs with
				// nothing to say which is dead. A race whose loser can safely repeat its
				// work is a retry; one that has already published a side effect is not.
				.onErrorResume(OptimisticLockingFailureException.class, lostRace -> {
					LOG.info("first-admin bootstrap: a sibling replica armed the printed credential first; "
							+ "standing down (its credential is the live one)");
					return Mono.empty();
				}).then();
	}

	Mono<Boolean> hasPlatformAdmin() {
		return roles.findAll().collectMap(PlatformRole::id).flatMap(roleById -> bindings.findAll().any(binding -> {
			PlatformRole role = roleById.get(binding.roleId());
			return role != null && role.permissions() != null
					&& role.permissions().contains(PlatformPermissions.USER_MANAGE)
					&& role.permissions().contains(PlatformPermissions.RBAC_WRITE);
		}));
	}

	private Mono<Long> completeBootstrap() {
		return db.sql(CLAIM_COMPLETION).fetch().rowsUpdated();
	}

	private Mono<OperatorSettings> ensureSettings() {
		return settings.findSingleton()
				.switchIfEmpty(Mono.defer(() -> settings.save(seededDefaults()))
						.onErrorResume(conflict -> settings.findSingleton()))
				.flatMap(this::reconcileSessionLimitDefaults).doOnNext(BootstrapService::warnWhenCapUnlimited);
	}

	// FR-SESS-3: the cluster-default session-limit knobs (concurrent cap, max
	// duration, idle timeout) are OPT-IN deployment-config values
	// (sessionlayer.session-limits.default-*). Seed them into a freshly-created
	// singleton, and — since the singleton may already have been created null at
	// cold start — reconcile each on every boot when its property is set
	// (deployment config is authoritative for the cluster default); when unset,
	// leave the stored value untouched (default null ⇒ unlimited/none), so
	// existing deployments are unaffected.
	private OperatorSettings seededDefaults() {
		return applyConfigured(OperatorSettings.defaults());
	}

	// Re-read and retry once on a lost write. A rolling update boots two replicas
	// together, both see stored != property on the rollout that first sets one, and
	// both save with the version they read; the loser's exception propagates out of
	// this runner and aborts the context, so the pod fails to start over a race
	// nobody caused. The manifest already reasoned about concurrent pod boot and
	// solved it for Flyway, which takes a database-level lock — this path has
	// optimistic locking instead and the same exposure. On the retry the row
	// already matches, so no save is attempted.
	private Mono<OperatorSettings> reconcileSessionLimitDefaults(OperatorSettings current) {
		OperatorSettings reconciled = applyConfigured(current);
		if (reconciled == current) {
			return Mono.just(current);
		}
		return settings.save(reconciled).onErrorResume(OptimisticLockingFailureException.class, lostRace -> {
			LOG.info("session-limit reconcile lost a concurrent write (a sibling replica booted at the same time); "
					+ "re-reading and retrying once");
			return settings.findSingleton().flatMap(fresh -> {
				OperatorSettings again = applyConfigured(fresh);
				return again == fresh ? Mono.just(fresh) : settings.save(again);
			});
		});
	}

	private OperatorSettings applyConfigured(OperatorSettings base) {
		OperatorSettings result = base;
		Integer concurrent = sessionLimits.getDefaultMaxConcurrent();
		if (concurrent != null && !concurrent.equals(result.defaultMaxConcurrentSessions())) {
			result = result.withDefaultMaxConcurrentSessions(concurrent);
		}
		Integer maxSeconds = sessionLimits.getDefaultMaxSessionSeconds();
		if (maxSeconds != null && !maxSeconds.equals(result.defaultMaxSessionSeconds())) {
			result = result.withDefaultMaxSessionSeconds(maxSeconds);
		}
		Integer idleSeconds = sessionLimits.getDefaultIdleTimeoutSeconds();
		if (idleSeconds != null && !idleSeconds.equals(result.defaultIdleTimeoutSeconds())) {
			result = result.withDefaultIdleTimeoutSeconds(idleSeconds);
		}
		return result;
	}

	// An unlimited cluster-default concurrent cap is a legitimate but
	// easily-unintended posture — say so once, loudly, at boot.
	private static void warnWhenCapUnlimited(OperatorSettings current) {
		if (current.defaultMaxConcurrentSessions() == null) {
			LOG.warn("the cluster-default concurrent-session cap is UNLIMITED: identities without a matching "
					+ "session_limit_policy have no concurrent-session bound. Set "
					+ "sessionlayer.session-limits.default-max-concurrent (or "
					+ "operator_settings.default_max_concurrent_sessions) to cap them.");
		}
	}

	private static OperatorSettings withCredentialHash(OperatorSettings s, String hash) {
		return new OperatorSettings(s.id(), s.singleton(), s.kekReference(), s.defaultCaBackend(),
				s.auditRetentionDays(), s.defaultWormMode(), s.otpTtlSeconds(), s.defaultMaxSessionSeconds(),
				s.defaultIdleTimeoutSeconds(), s.defaultMaxConcurrentSessions(), s.bootstrapAdminSubject(), hash,
				s.bootstrapCompleted(), s.bootstrapCompletedAt(), s.recordingCustomerPublicKey(),
				s.recordingKeySealAlgorithm(), s.recordingKeyRef(), s.recordingRetentionDays(),
				s.recordingStrictDefault(), s.origin(), s.version(), s.createdAt(), s.updatedAt());
	}
}
