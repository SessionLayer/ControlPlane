package io.sessionlayer.controlplane.web;

import static org.assertj.core.api.Assertions.assertThat;

import io.sessionlayer.controlplane.api.model.IssuedGatewayEnrollmentToken;
import io.sessionlayer.controlplane.data.config.PlatformRole;
import io.sessionlayer.controlplane.data.config.PlatformRoleRepository;
import io.sessionlayer.controlplane.data.config.RoleBinding;
import io.sessionlayer.controlplane.data.config.RoleBindingRepository;
import io.sessionlayer.controlplane.data.config.ServiceAccount;
import io.sessionlayer.controlplane.data.config.ServiceAccountRepository;
import io.sessionlayer.controlplane.data.runtime.AuditEvent;
import io.sessionlayer.controlplane.data.runtime.AuditEventRepository;
import io.sessionlayer.controlplane.gateway.SingleUseTokens;
import io.sessionlayer.controlplane.machine.MachineIdentityService;
import io.sessionlayer.controlplane.platform.PlatformPermissions;
import io.sessionlayer.controlplane.support.AbstractAuthIT;
import java.time.Duration;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webtestclient.autoconfigure.AutoConfigureWebTestClient;
import org.springframework.http.MediaType;
import org.springframework.r2dbc.core.DatabaseClient;
import org.springframework.test.web.reactive.server.WebTestClient;

@AutoConfigureWebTestClient
class GatewayEnrollmentTokenCrudIT extends AbstractAuthIT {

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
	AuditEventRepository auditEvents;
	@Autowired
	DatabaseClient db;

	@Test
	void issueReturnsTheRawTokenOnceAndPersistsOnlyItsHash() {
		String admin = "svc-ge-admin-" + UUID.randomUUID();
		String bearer = tokenWith(admin, PlatformPermissions.GATEWAY_ENROLL);
		String gateway = "ge-gw-" + UUID.randomUUID();

		IssuedGatewayEnrollmentToken issued = client.post().uri("/v1/gateway-enrollment-tokens")
				.header("Authorization", "Bearer " + bearer).contentType(MediaType.APPLICATION_JSON)
				.bodyValue(Map.of("gatewayName", gateway)).exchange().expectStatus().isCreated()
				.expectBody(IssuedGatewayEnrollmentToken.class).returnResult().getResponseBody();

		assertThat(issued.getToken()).isNotBlank();
		assertThat(issued.getGatewayName()).isEqualTo(gateway);
		assertThat(issued.getSingleUse()).isTrue();
		assertThat(issued.getExpiresAt()).isAfter(OffsetDateTime.now());

		String storedHash = db.sql("SELECT token_hash FROM runtime.gateway_enrollment_token WHERE id = :id")
				.bind("id", issued.getId()).map(row -> row.get("token_hash", String.class)).one().block();
		assertThat(storedHash).isEqualTo(SingleUseTokens.hash(issued.getToken())).isNotEqualTo(issued.getToken());

		Long rawAnywhere = db.sql("SELECT count(*) AS c FROM runtime.gateway_enrollment_token WHERE token_hash = :raw")
				.bind("raw", issued.getToken()).map(row -> row.get("c", Long.class)).one().block();
		assertThat(rawAnywhere).isZero();

		List<AuditEvent> audit = auditEvents.findByActor(admin).collectList().block();
		assertThat(audit).anySatisfy(event -> {
			assertThat(event.action()).isEqualTo("gateway_enrollment_token.issue");
			assertThat(event.outcome()).isEqualTo("success");
			assertThat(event.subject()).isEqualTo(issued.getId().toString());
		});
	}

	@Test
	void listCarriesMetadataButNeverTheRawToken() {
		String admin = "svc-ge-list-" + UUID.randomUUID();
		String bearer = tokenWith(admin, PlatformPermissions.GATEWAY_ENROLL);
		String gateway = "ge-list-" + UUID.randomUUID();

		IssuedGatewayEnrollmentToken issued = client.post().uri("/v1/gateway-enrollment-tokens")
				.header("Authorization", "Bearer " + bearer).contentType(MediaType.APPLICATION_JSON)
				.bodyValue(Map.of("gatewayName", gateway)).exchange().expectStatus().isCreated()
				.expectBody(IssuedGatewayEnrollmentToken.class).returnResult().getResponseBody();

		// Assert on the serialized body, not a DTO field: a leak would be a stray
		// property no typed getter would show.
		String body = client.get().uri("/v1/gateway-enrollment-tokens").header("Authorization", "Bearer " + bearer)
				.exchange().expectStatus().isOk().expectBody(String.class).returnResult().getResponseBody();

		assertThat(body).contains(gateway).contains(issued.getId().toString()).contains(admin)
				.doesNotContain(issued.getToken()).doesNotContain(SingleUseTokens.hash(issued.getToken()))
				.doesNotContain("\"token\"").doesNotContain("tokenHash");
	}

	@Test
	void everyRouteRequiresGatewayEnroll() {
		String stranger = "svc-ge-none-" + UUID.randomUUID();
		String bearer = tokenWith(stranger);

		client.post().uri("/v1/gateway-enrollment-tokens").header("Authorization", "Bearer " + bearer)
				.contentType(MediaType.APPLICATION_JSON).bodyValue(Map.of("gatewayName", "ge-denied")).exchange()
				.expectStatus().isForbidden();
		client.get().uri("/v1/gateway-enrollment-tokens").header("Authorization", "Bearer " + bearer).exchange()
				.expectStatus().isForbidden();
		client.delete().uri("/v1/gateway-enrollment-tokens/" + UUID.randomUUID())
				.header("Authorization", "Bearer " + bearer).exchange().expectStatus().isForbidden();
		client.get().uri("/v1/cas/mtls/trust-anchor").header("Authorization", "Bearer " + bearer).exchange()
				.expectStatus().isForbidden();

		Long minted = db.sql("SELECT count(*) AS c FROM runtime.gateway_enrollment_token WHERE gateway_name = :n")
				.bind("n", "ge-denied").map(row -> row.get("c", Long.class)).one().block();
		assertThat(minted).isZero();
	}

	@Test
	void holdingCaManageAloneDoesNotGrantEnrollment() {
		String caAdmin = "svc-ge-ca-" + UUID.randomUUID();
		String bearer = tokenWith(caAdmin, PlatformPermissions.CA_MANAGE);

		client.get().uri("/v1/cas/mtls/trust-anchor").header("Authorization", "Bearer " + bearer).exchange()
				.expectStatus().isForbidden();
		client.get().uri("/v1/gateway-enrollment-tokens").header("Authorization", "Bearer " + bearer).exchange()
				.expectStatus().isForbidden();
	}

	@Test
	void anInvalidGatewayNameIsRejectedAndPersistsNothing() {
		String admin = "svc-ge-bad-" + UUID.randomUUID();
		String bearer = tokenWith(admin, PlatformPermissions.GATEWAY_ENROLL);

		client.post().uri("/v1/gateway-enrollment-tokens").header("Authorization", "Bearer " + bearer)
				.contentType(MediaType.APPLICATION_JSON).bodyValue(Map.of("gatewayName", "bad name!")).exchange()
				.expectStatus().isBadRequest().expectHeader()
				.contentTypeCompatibleWith(MediaType.APPLICATION_PROBLEM_JSON).expectBody().jsonPath("$.title")
				.isEqualTo("Malformed request");

		Long minted = db.sql("SELECT count(*) AS c FROM runtime.gateway_enrollment_token WHERE gateway_name = :n")
				.bind("n", "bad name!").map(row -> row.get("c", Long.class)).one().block();
		assertThat(minted).isZero();

		List<AuditEvent> audit = auditEvents.findByActor(admin).collectList().block();
		assertThat(audit).noneSatisfy(event -> assertThat(event.action()).isEqualTo("gateway_enrollment_token.issue"));
	}

	/**
	 * The name becomes the CN and dNSName SAN of a serverAuth leaf, so minting for
	 * the CP's own hostname would hand a gateway:enroll holder a CA-signed
	 * certificate that impersonates the Control Plane.
	 */
	@Test
	void mintingForTheControlPlanesOwnHostnameIsRefused() {
		String admin = "svc-ge-cp-" + UUID.randomUUID();
		String bearer = tokenWith(admin, PlatformPermissions.GATEWAY_ENROLL);

		for (String reserved : List.of("controlplane", "CONTROLPLANE", "controlplane.", "localhost")) {
			client.post().uri("/v1/gateway-enrollment-tokens").header("Authorization", "Bearer " + bearer)
					.contentType(MediaType.APPLICATION_JSON).bodyValue(Map.of("gatewayName", reserved)).exchange()
					.expectStatus().isBadRequest();

			Long minted = db.sql("SELECT count(*) AS c FROM runtime.gateway_enrollment_token WHERE gateway_name = :n")
					.bind("n", reserved).map(row -> row.get("c", Long.class)).one().block();
			assertThat(minted).as("no token persisted for reserved name %s", reserved).isZero();
		}
	}

	@Test
	void ttlIsClampedToTheConfiguredMaximum() {
		String admin = "svc-ge-ttl-" + UUID.randomUUID();
		String bearer = tokenWith(admin, PlatformPermissions.GATEWAY_ENROLL);

		IssuedGatewayEnrollmentToken issued = client.post().uri("/v1/gateway-enrollment-tokens")
				.header("Authorization", "Bearer " + bearer).contentType(MediaType.APPLICATION_JSON)
				.bodyValue(Map.of("gatewayName", "ge-ttl-" + UUID.randomUUID(), "ttlSeconds", 86400)).exchange()
				.expectStatus().isCreated().expectBody(IssuedGatewayEnrollmentToken.class).returnResult()
				.getResponseBody();

		// Default max is one hour; a day must not survive the clamp.
		assertThat(issued.getExpiresAt().toInstant()).isBefore(Instant.now().plus(Duration.ofHours(2)));
	}

	@Test
	void revokeIsIdempotentAndAudited() {
		String admin = "svc-ge-revoke-" + UUID.randomUUID();
		String bearer = tokenWith(admin, PlatformPermissions.GATEWAY_ENROLL);
		String gateway = "ge-revoke-" + UUID.randomUUID();

		IssuedGatewayEnrollmentToken issued = client.post().uri("/v1/gateway-enrollment-tokens")
				.header("Authorization", "Bearer " + bearer).contentType(MediaType.APPLICATION_JSON)
				.bodyValue(Map.of("gatewayName", gateway)).exchange().expectStatus().isCreated()
				.expectBody(IssuedGatewayEnrollmentToken.class).returnResult().getResponseBody();

		client.delete().uri("/v1/gateway-enrollment-tokens/" + issued.getId())
				.header("Authorization", "Bearer " + bearer).exchange().expectStatus().isNoContent();
		client.delete().uri("/v1/gateway-enrollment-tokens/" + issued.getId())
				.header("Authorization", "Bearer " + bearer).exchange().expectStatus().isNoContent();
		client.delete().uri("/v1/gateway-enrollment-tokens/" + UUID.randomUUID())
				.header("Authorization", "Bearer " + bearer).exchange().expectStatus().isNoContent();

		// cp_runtime holds no DELETE here: the row must survive, marked consumed.
		Map<String, Object> row = db
				.sql("SELECT consumed_at, token_hash FROM runtime.gateway_enrollment_token WHERE id = :id")
				.bind("id", issued.getId()).map(r -> Map.<String, Object>of("consumedAt",
						r.get("consumed_at", Instant.class), "tokenHash", r.get("token_hash", String.class)))
				.one().block();
		assertThat(row).isNotNull();
		assertThat(row.get("consumedAt")).isNotNull();

		String list = client.get().uri("/v1/gateway-enrollment-tokens").header("Authorization", "Bearer " + bearer)
				.exchange().expectStatus().isOk().expectBody(String.class).returnResult().getResponseBody();
		assertThat(list).doesNotContain(gateway);

		List<AuditEvent> audit = auditEvents.findByActor(admin).collectList().block();
		assertThat(audit).anySatisfy(event -> {
			assertThat(event.action()).isEqualTo("gateway_enrollment_token.revoke");
			assertThat(event.subject()).isEqualTo(issued.getId().toString());
		});
	}

	private String tokenWith(String saName, String... permissions) {
		ServiceAccount sa = serviceAccounts
				.save(ServiceAccount.create(saName, "test", "client_secret", null, null, "api")).block();
		var issued = machineIdentity.issueCredential(sa.id(), "client_secret", null, null, null, null, "admin").block();
		if (permissions.length > 0) {
			PlatformRole role = roles
					.save(PlatformRole.create("ge-role-" + UUID.randomUUID(), List.of(permissions), "test", "default"))
					.block();
			bindings.save(RoleBinding.create(role.id(), "user", saName, null, "default")).block();
		}
		var token = machineIdentity.issueToken(new MachineIdentityService.TokenRequest("client_credentials", saName,
				null, null, issued.clientSecret(), null), null, "203.0.113.31").block();
		return token.accessToken();
	}
}
