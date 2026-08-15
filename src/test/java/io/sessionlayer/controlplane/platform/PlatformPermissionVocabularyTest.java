package io.sessionlayer.controlplane.platform;

import static org.assertj.core.api.Assertions.assertThat;

import io.sessionlayer.controlplane.api.model.PlatformPermission;
import java.util.Arrays;
import java.util.List;
import org.junit.jupiter.api.Test;

/**
 * The permission vocabulary is closed and copied. Two copies are
 * machine-readable: {@link PlatformPermissions#ALL}, the source of truth the
 * server enforces against, and the {@code PlatformPermission} enum in the
 * vendored OpenAPI spec — which is what a role-write request may name, so a
 * permission missing from it is one an admin cannot grant however correctly the
 * server enforces it. The SQL {@code platform_role_permissions_check} copy is
 * already guarded by {@code MigrationIntegrityIT}; this closes the other.
 *
 * <p>
 * Not a cross-repo drift checker: the spec is vendored into this build and the
 * enum here is generated from that vendored copy, so both sides of this
 * comparison are artifacts of the same build.
 */
class PlatformPermissionVocabularyTest {

	@Test
	void theApiVocabularyIsExactlyTheEnforcedOne() {
		List<String> published = Arrays.stream(PlatformPermission.values()).map(PlatformPermission::getValue).sorted()
				.toList();
		List<String> enforced = PlatformPermissions.ALL.stream().sorted().toList();

		// Both directions at once: a permission in either copy and not the other fails,
		// and the message names it.
		assertThat(published).containsExactlyElementsOf(enforced);
	}
}
