package io.sessionlayer.controlplane.web;

import static org.assertj.core.api.Assertions.assertThat;

import io.sessionlayer.controlplane.data.config.PlatformRole;
import io.sessionlayer.controlplane.data.config.PlatformRoleRepository;
import io.sessionlayer.controlplane.data.config.RoleBinding;
import io.sessionlayer.controlplane.data.config.RoleBindingRepository;
import io.sessionlayer.controlplane.data.config.ServiceAccount;
import io.sessionlayer.controlplane.data.config.ServiceAccountRepository;
import io.sessionlayer.controlplane.machine.MachineIdentityService;
import io.sessionlayer.controlplane.platform.PlatformPermissions;
import io.sessionlayer.controlplane.support.AbstractAuthIT;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webtestclient.autoconfigure.AutoConfigureWebTestClient;
import org.springframework.http.MediaType;
import org.springframework.test.web.reactive.server.WebTestClient;

/**
 * The metrics endpoints were authenticated but not authorized: a token minted
 * for a service account with no role binding at all read the whole meter set -
 * fleet-wide live-session counts, authorization error rates, CA-signer
 * activity, session-limit denials. Every machine identity the platform had ever
 * issued could read it.
 */
@AutoConfigureWebTestClient
class MetricsAuthorizationIT extends AbstractAuthIT {

	@Autowired
	WebTestClient client;
	@Autowired
	MachineIdentityService machineIdentity;
	@Autowired
	ServiceAccountRepository serviceAccounts;
	@Autowired
	PlatformRoleRepository roles;
	@Autowired
	RoleBindingRepository bindings;

	@Test
	void aRoleCarryingMetricsReadCanBeCreated() {
		String token = tokenWith("svc-metrics-rbac-" + unique(), PlatformPermissions.RBAC_WRITE);

		// The vocabulary is closed in four places and the database CHECK is the one
		// that fails in the wrong direction: it would reject the permission as
		// out-of-vocabulary, so nobody could grant it and the endpoint would stay
		// exactly as exposed as before, while every other surface looked correct. This
		// asserts the CHECK really widened, not just the constant.
		client.post().uri("/v1/roles").header("Authorization", "Bearer " + token)
				.contentType(MediaType.APPLICATION_JSON)
				.bodyValue(Map.of("name", "scraper-" + unique(), "permissions", List.of("metrics:read"))).exchange()
				.expectStatus().isCreated().expectBody().jsonPath("$.permissions[0]").isEqualTo("metrics:read");
	}

	@Test
	void aTokenHoldingMetricsReadScrapesAndOneWithoutItIsRefused() {
		String scraper = tokenWith("svc-metrics-ok-" + unique(), PlatformPermissions.METRICS_READ);
		client.get().uri("/actuator/prometheus").header("Authorization", "Bearer " + scraper).exchange().expectStatus()
				.isOk().expectBody(String.class).value(body -> assertThat(body).isNotBlank());

		String unbound = tokenWith("svc-metrics-none-" + unique());
		client.get().uri("/actuator/prometheus").header("Authorization", "Bearer " + unbound).exchange().expectStatus()
				.isForbidden();
		client.get().uri("/actuator/metrics").header("Authorization", "Bearer " + unbound).exchange().expectStatus()
				.isForbidden();

		// A different permission is not a substitute - reusing audit:read here would
		// have handed a scraper the whole audit trail to read a gauge.
		String auditor = tokenWith("svc-metrics-auditor-" + unique(), PlatformPermissions.AUDIT_READ);
		client.get().uri("/actuator/prometheus").header("Authorization", "Bearer " + auditor).exchange().expectStatus()
				.isForbidden();
	}

	@Test
	void theProbeEndpointsStayPublic() {
		// Kubernetes liveness/readiness carry no token; gating metrics must not reach
		// them. The assertion is REACHABILITY, not the health verdict: a probe that is
		// answered 503 because a contributor is down has still passed the security
		// chain, which is what this test is about - 401 or 403 would mean the gate
		// swallowed the probe.
		client.get().uri("/actuator/health").exchange().expectStatus()
				.value(status -> assertThat(status).isNotIn(401, 403));
		client.get().uri("/actuator/info").exchange().expectStatus()
				.value(status -> assertThat(status).isNotIn(401, 403));
		client.get().uri("/actuator/prometheus").exchange().expectStatus().isUnauthorized();
	}

	private String tokenWith(String saName, String... permissions) {
		ServiceAccount sa = serviceAccounts
				.save(ServiceAccount.create(saName, "test", "client_secret", null, null, "api")).block();
		var issued = machineIdentity.issueCredential(sa.id(), "client_secret", null, null, null, null, "admin").block();
		if (permissions.length > 0) {
			PlatformRole role = roles.save(
					PlatformRole.create("metrics-role-" + UUID.randomUUID(), List.of(permissions), "test", "default"))
					.block();
			bindings.save(RoleBinding.create(role.id(), "user", saName, null, "default")).block();
		}
		var token = machineIdentity.issueToken(new MachineIdentityService.TokenRequest("client_credentials", saName,
				null, null, issued.clientSecret(), null), null, "203.0.113.30").block();
		return token.accessToken();
	}

	private static String unique() {
		return UUID.randomUUID().toString().substring(0, 8);
	}
}
