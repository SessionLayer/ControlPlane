package io.sessionlayer.controlplane.data;

import static org.assertj.core.api.Assertions.assertThat;

import io.sessionlayer.controlplane.platform.PlatformPermissions;
import io.sessionlayer.controlplane.support.AbstractAuthIT;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.Arrays;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.core.io.Resource;
import org.springframework.core.io.support.PathMatchingResourcePatternResolver;

/**
 * The vocabulary back-fill, proven against the real migration text rather than
 * a restatement of it.
 *
 * <p>
 * The defect it repairs is invisible on a fresh install, which is why four
 * migrations shipped without it: {@code ensureAdminRole()} is create-only and
 * the bootstrap returns early once completed, so an already-bootstrapped
 * deployment's admin role keeps whatever vocabulary existed when it was seeded.
 * These tests seed exactly that stale row and re-run the shipped script over it
 * - it is written to be idempotent, so re-running is the honest way to exercise
 * it.
 *
 * <p>
 * It replays the <b>newest</b> migration that rewrites
 * {@code platform_role_permissions_check}, discovered rather than named. Naming
 * one froze the test to the vocabulary of the day it was written: replaying V29
 * verbatim re-added a CHECK listing twenty permissions, which the first
 * twenty-first permission then violated on rows that legitimately carry it. The
 * guarantee under test is not "V29 worked once", it is "the current vocabulary
 * migration reconciles a stale seeded role against the WHOLE vocabulary" - and
 * that is the behaviour every future one has to inherit.
 */
class PlatformAdminBackfillIT extends AbstractAuthIT {

	// The vocabulary as it stood before V18, i.e. what a deployment bootstrapped
	// at that point still carries today.
	private static final List<String> STALE_VOCABULARY = List.of("rbac:read", "rbac:write", "node:enroll",
			"node:quarantine", "node:remove", "ca:manage", "ca:rotate", "request:approve", "recording:replay",
			"recording:export", "audit:read", "user:manage", "settings:write");

	@BeforeEach
	@AfterEach
	void removeAdminRole() throws Exception {
		execute("DELETE FROM config.role_binding WHERE role_id IN"
				+ " (SELECT id FROM config.platform_role WHERE name = 'platform-admin')");
		execute("DELETE FROM config.platform_role WHERE name = 'platform-admin'");
	}

	@Test
	void aStaleSeededRoleGainsEveryMissingPermission() throws Exception {
		seedAdminRole(STALE_VOCABULARY, "default");

		runVocabularyMigration();

		assertThat(adminPermissions()).containsAll(PlatformPermissions.ALL)
				.contains("gateway:enroll", "gateway:remove", "recording:key-manage", "lock:read", "lock:write",
						"breakglass:manage", "recording:delete")
				// Nothing outside the closed vocabulary is invented.
				.allSatisfy(permission -> assertThat(PlatformPermissions.ALL).contains(permission));
	}

	@Test
	void theBackfillIsIdempotent() throws Exception {
		seedAdminRole(STALE_VOCABULARY, "default");

		runVocabularyMigration();
		List<String> once = adminPermissions();
		runVocabularyMigration();
		List<String> twice = adminPermissions();

		assertThat(twice).containsExactlyElementsOf(once);
		assertThat(twice).doesNotHaveDuplicates();
	}

	// A role an operator curated through /v1/roles may be deliberately narrower,
	// and silently restoring a permission they removed would be the worse failure.
	@Test
	void anOperatorCuratedRoleIsLeftAlone() throws Exception {
		seedAdminRole(STALE_VOCABULARY, "api");

		runVocabularyMigration();

		assertThat(adminPermissions()).containsExactlyInAnyOrderElementsOf(STALE_VOCABULARY)
				.doesNotContain("gateway:enroll", "recording:key-manage");
	}

	private void seedAdminRole(List<String> permissions, String origin) throws Exception {
		String array = "ARRAY['" + String.join("','", permissions) + "']::text[]";
		execute("INSERT INTO config.platform_role (id, name, permissions, description, origin) VALUES ('"
				+ UUID.randomUUID() + "', 'platform-admin', " + array + ", 'seeded before the new verbs existed', '"
				+ origin + "')");
	}

	private void runVocabularyMigration() throws Exception {
		execute(newestVocabularyMigration());
	}

	private static String newestVocabularyMigration() throws Exception {
		Resource[] migrations = new PathMatchingResourcePatternResolver()
				.getResources("classpath*:db/migration/V*.sql");
		String newest = null;
		int newestVersion = -1;
		for (Resource migration : migrations) {
			String body = new String(migration.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
			if (!body.contains("platform_role_permissions_check")) {
				continue;
			}
			int version = Integer.parseInt(migration.getFilename().substring(1).split("__")[0]);
			if (version > newestVersion) {
				newestVersion = version;
				newest = body;
			}
		}
		assertThat(newest).as("a migration defining platform_role_permissions_check is on the classpath").isNotNull();
		return newest;
	}

	private List<String> adminPermissions() throws Exception {
		try (Connection connection = POSTGRES.createConnection("");
				Statement statement = connection.createStatement();
				ResultSet rows = statement
						.executeQuery("SELECT permissions FROM config.platform_role WHERE name = 'platform-admin'")) {
			assertThat(rows.next()).as("the platform-admin role exists").isTrue();
			return Arrays.asList((String[]) rows.getArray(1).getArray());
		}
	}

	private void execute(String sql) throws Exception {
		try (Connection connection = POSTGRES.createConnection("");
				Statement statement = connection.createStatement()) {
			statement.execute(sql);
		}
	}
}
