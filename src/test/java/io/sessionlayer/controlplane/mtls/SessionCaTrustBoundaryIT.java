package io.sessionlayer.controlplane.mtls;

import static org.assertj.core.api.Assertions.assertThat;

import io.sessionlayer.controlplane.ca.CaRotationService;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

class SessionCaTrustBoundaryIT extends AbstractMtlsIT {

	@Autowired
	private CaRotationService caRotation;

	@Test
	void theNodeTrustsOnlyTheSessionCaAndNeverAStandingBreakGlassCa() {
		List<String> sessionTrust = caRotation.trustedCaKeys("session").block();
		List<String> hostTrust = caRotation.trustedCaKeys("host").block();
		List<String> userTrust = caRotation.trustedCaKeys("user").block();
		List<String> breakglassTrust = caRotation.trustedCaKeys("breakglass").block();
		assertThat(sessionTrust).isNotEmpty();
		assertThat(sessionTrust).doesNotContainAnyElementsOf(hostTrust).doesNotContainAnyElementsOf(userTrust);
		assertThat(breakglassTrust).isEmpty();

		List<String> kinds = db.sql("SELECT DISTINCT ca_kind FROM config.ca_config")
				.map(row -> row.get("ca_kind", String.class)).all().collectList().block();
		assertThat(kinds).contains("session", "user", "host").doesNotContain("breakglass");
	}
}
