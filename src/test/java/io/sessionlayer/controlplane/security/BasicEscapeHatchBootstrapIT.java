package io.sessionlayer.controlplane.security;

import static org.assertj.core.api.Assertions.assertThat;

import io.sessionlayer.controlplane.api.model.OperatorSettings;
import io.sessionlayer.controlplane.auth.Secrets;
import io.sessionlayer.controlplane.data.config.PlatformRole;
import io.sessionlayer.controlplane.data.config.PlatformRoleRepository;
import io.sessionlayer.controlplane.platform.PlatformPermissions;
import io.sessionlayer.controlplane.support.AbstractAuthIT;
import java.nio.charset.StandardCharsets;
import java.security.KeyPairGenerator;
import java.security.spec.ECGenParameterSpec;
import java.util.Base64;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpHeaders;
import org.springframework.r2dbc.core.DatabaseClient;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.reactive.server.WebTestClient;

/**
 * The credential-only first-install path: an operator holding no database
 * credential authenticates with the
 * {@code sessionlayer.rest-security.basic-auth} escape hatch, claims the
 * printed bootstrap credential to bind that same username as the first admin,
 * and must then resolve the {@code platform-admin} role's permissions on the
 * config API.
 *
 * <p>
 * Needs a real socket: the escape hatch is CIDR-gated on the peer address,
 * which a mock exchange does not have.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, properties = {
		"sessionlayer.mtls.server.port=0", "sessionlayer.auth.token-endpoint.max=1000000",
		"management.health.worm.enabled=false"})
class BasicEscapeHatchBootstrapIT extends AbstractAuthIT {

	private static final String INSTALLER = "installer";
	private static final String PASSWORD = "install-time-secret";

	@DynamicPropertySource
	static void escapeHatch(DynamicPropertyRegistry registry) {
		registry.add("sessionlayer.rest-security.basic-auth.enabled", () -> "true");
		registry.add("sessionlayer.rest-security.basic-auth.username", () -> INSTALLER);
		registry.add("sessionlayer.rest-security.basic-auth.password-hash",
				() -> new BCryptPasswordEncoder().encode(PASSWORD));
		registry.add("sessionlayer.rest-security.basic-auth.allowed-cidrs", () -> "127.0.0.1/32,::1/128");
	}

	@Autowired
	private PlatformRoleRepository roles;
	@Autowired
	private DatabaseClient db;

	@Value("${local.server.port}")
	private int port;

	private WebTestClient http;

	@BeforeEach
	void resetBootstrapAndBind() {
		db.sql("DELETE FROM config.role_binding WHERE role_id IN (SELECT id FROM config.platform_role"
				+ " WHERE name = 'platform-admin')").fetch().rowsUpdated().block();
		db.sql("DELETE FROM config.platform_role WHERE name = 'platform-admin'").fetch().rowsUpdated().block();
		db.sql("UPDATE config.operator_settings SET bootstrap_completed = false, bootstrap_completed_at = null,"
				+ " bootstrap_credential_hash = :hash, default_worm_mode = 'governance',"
				+ " recording_customer_public_key = null WHERE singleton = true")
				.bind("hash", Secrets.sha256Hex("printed-once-credential")).fetch().rowsUpdated().block();
		http = WebTestClient.bindToServer().baseUrl("http://127.0.0.1:" + port).build();
	}

	@Test
	void basicSubjectBoundByBootstrapClaimResolvesAdminPermissions() {
		http.post().uri("/v1/bootstrap/claim").header(HttpHeaders.CONTENT_TYPE, "application/json")
				.bodyValue("{\"credential\":\"printed-once-credential\",\"subject\":\"" + INSTALLER + "\"}").exchange()
				.expectStatus().isOk();

		PlatformRole admin = roles.findByName("platform-admin").block();
		assertThat(admin).isNotNull();
		assertThat(admin.permissions()).containsExactlyInAnyOrderElementsOf(PlatformPermissions.ALL);

		// rbac:read and ca:manage are distinct permissions on the admin role — both
		// resolving proves the whole grant, not one lucky verb.
		http.get().uri("/v1/session-limit-policies").header(HttpHeaders.AUTHORIZATION, basic(INSTALLER, PASSWORD))
				.exchange().expectStatus().isOk();
		http.get().uri("/v1/cas").header(HttpHeaders.AUTHORIZATION, basic(INSTALLER, PASSWORD)).exchange()
				.expectStatus().isOk();
	}

	/**
	 * The two writes a first install cannot complete without: the operator settings
	 * and the customer recording key, which strict recording refuses every session
	 * without. They sit on different permissions, and the recording key's is new,
	 * so this is where a vocabulary that did not reach the seeded role would show
	 * up as a 403 at the worst moment.
	 */
	@Test
	void theBoundBasicSubjectCanCompleteTheInstallWrites() {
		http.post().uri("/v1/bootstrap/claim").header(HttpHeaders.CONTENT_TYPE, "application/json")
				.bodyValue("{\"credential\":\"printed-once-credential\",\"subject\":\"" + INSTALLER + "\"}").exchange()
				.expectStatus().isOk();

		Long version = http.get().uri("/v1/operator-settings")
				.header(HttpHeaders.AUTHORIZATION, basic(INSTALLER, PASSWORD)).exchange().expectStatus().isOk()
				.expectBody(OperatorSettings.class).returnResult().getResponseBody().getVersion();

		http.put().uri("/v1/operator-settings").header(HttpHeaders.AUTHORIZATION, basic(INSTALLER, PASSWORD))
				.header(HttpHeaders.CONTENT_TYPE, "application/json")
				.bodyValue(Map.of("auditRetentionDays", 365, "recordingRetentionDays", 365, "defaultWormMode",
						"compliance", "otpTtlSeconds", 120, "version", version))
				.exchange().expectStatus().isOk();

		http.put().uri("/v1/operator-settings/recording-customer-key")
				.header(HttpHeaders.AUTHORIZATION, basic(INSTALLER, PASSWORD))
				.header(HttpHeaders.CONTENT_TYPE, "application/json")
				.bodyValue(Map.of("publicKey", p256Spki(), "sealAlgorithm", "ecies_p256", "version", version + 1))
				.exchange().expectStatus().isOk().expectBody().jsonPath("$.configured").isEqualTo(true);
	}

	private static String p256Spki() {
		try {
			KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
			generator.initialize(new ECGenParameterSpec("secp256r1"));
			return Base64.getEncoder().encodeToString(generator.generateKeyPair().getPublic().getEncoded());
		} catch (Exception unavailable) {
			throw new IllegalStateException(unavailable);
		}
	}

	@Test
	void unboundBasicSubjectIsRefusedOnTheConfigApi() {
		http.get().uri("/v1/session-limit-policies").header(HttpHeaders.AUTHORIZATION, basic(INSTALLER, PASSWORD))
				.exchange().expectStatus().isForbidden();
	}

	@Test
	void wrongBasicPasswordIsNotAuthenticated() {
		http.get().uri("/v1/session-limit-policies").header(HttpHeaders.AUTHORIZATION, basic(INSTALLER, "wrong"))
				.exchange().expectStatus().isUnauthorized();
	}

	private static String basic(String user, String password) {
		return "Basic " + Base64.getEncoder().encodeToString((user + ":" + password).getBytes(StandardCharsets.UTF_8));
	}
}
