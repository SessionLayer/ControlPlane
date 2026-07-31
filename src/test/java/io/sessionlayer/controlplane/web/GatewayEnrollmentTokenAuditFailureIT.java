package io.sessionlayer.controlplane.web;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;

import io.sessionlayer.controlplane.audit.AuditEventStore;
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
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webtestclient.autoconfigure.AutoConfigureWebTestClient;
import org.springframework.http.MediaType;
import org.springframework.r2dbc.core.DatabaseClient;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.reactive.server.WebTestClient;
import reactor.core.publisher.Mono;

/**
 * A mint that cannot be audited must not stand: the audit append and the token
 * INSERT share one transaction, so an audit sink failure has to take the token
 * row with it.
 */
@AutoConfigureWebTestClient
// The mocked sink is only stubbed once the test starts, so keep the startup
// bootstrap runner (which audits) out of this context entirely.
@TestPropertySource(properties = "sessionlayer.bootstrap.enabled=false")
class GatewayEnrollmentTokenAuditFailureIT extends AbstractAuthIT {

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
	@Autowired
	DatabaseClient db;

	@MockitoBean
	AuditEventStore audit;

	@BeforeEach
	void auditSucceedsExceptForTheMint() {
		when(audit.record(any(AuditEventStore.AuditRecord.class))).thenReturn(Mono.empty());
		when(audit.record(any(), any(), any(), any(), any(), any(), any())).thenReturn(Mono.empty());
		when(audit.recordChange(any(), any(), any(), any(), any(), any())).thenReturn(Mono.empty());
		when(audit.record(any(), any(), eq("gateway_enrollment_token.issue"), any(), any(), any(), any()))
				.thenReturn(Mono.error(new IllegalStateException("audit sink unavailable")));
	}

	@Test
	void aMintWhoseAuditWriteFailsLeavesNoToken() {
		String admin = "svc-ge-audit-" + UUID.randomUUID();
		String bearer = tokenWith(admin, PlatformPermissions.GATEWAY_ENROLL);
		String gateway = "ge-audit-" + UUID.randomUUID();

		client.post().uri("/v1/gateway-enrollment-tokens").header("Authorization", "Bearer " + bearer)
				.contentType(MediaType.APPLICATION_JSON).bodyValue(Map.of("gatewayName", gateway)).exchange()
				.expectStatus().is5xxServerError();

		Long minted = db.sql("SELECT count(*) AS c FROM runtime.gateway_enrollment_token WHERE gateway_name = :n")
				.bind("n", gateway).map(row -> row.get("c", Long.class)).one().block();
		assertThat(minted).isZero();
	}

	private String tokenWith(String saName, String... permissions) {
		ServiceAccount sa = serviceAccounts
				.save(ServiceAccount.create(saName, "test", "client_secret", null, null, "api")).block();
		var issued = machineIdentity.issueCredential(sa.id(), "client_secret", null, null, null, null, "admin").block();
		if (permissions.length > 0) {
			PlatformRole role = roles
					.save(PlatformRole.create("ga-role-" + UUID.randomUUID(), List.of(permissions), "test", "default"))
					.block();
			bindings.save(RoleBinding.create(role.id(), "user", saName, null, "default")).block();
		}
		var token = machineIdentity.issueToken(new MachineIdentityService.TokenRequest("client_credentials", saName,
				null, null, issued.clientSecret(), null), null, "203.0.113.33").block();
		return token.accessToken();
	}
}
