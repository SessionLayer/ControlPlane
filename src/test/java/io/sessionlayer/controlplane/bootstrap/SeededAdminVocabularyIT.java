package io.sessionlayer.controlplane.bootstrap;

import static org.assertj.core.api.Assertions.assertThat;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import io.sessionlayer.controlplane.data.config.PlatformRole;
import io.sessionlayer.controlplane.data.config.PlatformRoleRepository;
import io.sessionlayer.controlplane.platform.PlatformPermissions;
import io.sessionlayer.controlplane.support.AbstractAuthIT;
import java.util.List;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.r2dbc.core.DatabaseClient;

/**
 * The boot-time detector is the whole of the defence: nothing back-fills a
 * seeded admin role that predates a permission, so a role left short of the
 * vocabulary refuses every operation that permission gates and says nothing
 * about it. The detector deliberately never mutates, so the warning it emits -
 * and the silence it keeps over a role an operator curated - is its entire
 * observable behaviour.
 */
class SeededAdminVocabularyIT extends AbstractAuthIT {

	// The vocabulary as it stood before the lock verbs existed, i.e. what a
	// deployment bootstrapped at that point still carries today.
	private static final List<String> STALE_VOCABULARY = List.of("rbac:read", "rbac:write", "node:enroll",
			"node:quarantine", "node:remove", "ca:manage", "ca:rotate", "request:approve", "recording:replay",
			"recording:export", "audit:read", "user:manage", "settings:write");

	@Autowired
	private BootstrapService bootstrap;

	@Autowired
	private PlatformRoleRepository roles;

	@Autowired
	private DatabaseClient db;

	private final ListAppender<ILoggingEvent> appender = new ListAppender<>();

	@BeforeEach
	void seedAnAlreadyBootstrappedDeployment() {
		removeAdminRole();
		// The detector is reachable only past bootstrap - a fresh one seeds the
		// role with the whole vocabulary and has nothing to warn about.
		db.sql("UPDATE config.operator_settings SET bootstrap_completed = true WHERE singleton = true").fetch()
				.rowsUpdated().block();
		appender.start();
		bootstrapLogger().addAppender(appender);
	}

	@AfterEach
	void releaseTheLogger() {
		bootstrapLogger().detachAppender(appender);
		appender.stop();
		removeAdminRole();
	}

	@Test
	void aStaleSeededRoleIsWarnedAboutByPermissionName() {
		seedAdminRole(STALE_VOCABULARY, "default");

		bootstrap.runAtStartup().block();

		List<String> warnings = permissionNamingWarnings();
		assertThat(warnings).hasSize(1);
		assertThat(warnings.getFirst()).contains(missingFromStaleVocabulary()).doesNotContain(STALE_VOCABULARY);
	}

	@Test
	void aSeededRoleHoldingTheWholeVocabularyIsSilent() {
		seedAdminRole(List.copyOf(PlatformPermissions.ALL), "default");

		bootstrap.runAtStartup().block();

		assertThat(permissionNamingWarnings()).isEmpty();
	}

	// A role an operator curated through /v1/roles may be deliberately narrower,
	// and nagging them to restore a permission they removed teaches them to
	// ignore the one warning that matters.
	@Test
	void anOperatorCuratedRoleIsLeftAlone() {
		seedAdminRole(STALE_VOCABULARY, "api");

		bootstrap.runAtStartup().block();

		assertThat(permissionNamingWarnings()).isEmpty();
	}

	// The detector is the only thing here that names a permission, so this
	// isolates it without freezing the test to the warning's current wording.
	private List<String> permissionNamingWarnings() {
		return appender.list.stream().filter(event -> event.getLevel() == Level.WARN)
				.map(ILoggingEvent::getFormattedMessage)
				.filter(message -> PlatformPermissions.ALL.stream().anyMatch(message::contains)).toList();
	}

	// Derived rather than listed: a permission added later must widen what the
	// warning is required to name, or this freezes to today's vocabulary.
	private static List<String> missingFromStaleVocabulary() {
		return PlatformPermissions.ALL.stream().filter(permission -> !STALE_VOCABULARY.contains(permission)).toList();
	}

	private void seedAdminRole(List<String> permissions, String origin) {
		roles.save(PlatformRole.create("platform-admin", permissions, "seeded before the new verbs existed", origin))
				.block();
	}

	private void removeAdminRole() {
		db.sql("DELETE FROM config.role_binding WHERE role_id IN (SELECT id FROM config.platform_role"
				+ " WHERE name = 'platform-admin')").fetch().rowsUpdated().block();
		db.sql("DELETE FROM config.platform_role WHERE name = 'platform-admin'").fetch().rowsUpdated().block();
	}

	private static Logger bootstrapLogger() {
		return (Logger) LoggerFactory.getLogger(BootstrapService.class);
	}
}
