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
 * Two surfaces an operator could not use, and the reason both were hard to
 * diagnose. {@code GET /v1/pins} required the identity up front, which assumed
 * the caller already knew the answer to the question they were asking; and a
 * deny rule had to invent a {@code ttlSeconds} it has no use for, failing with
 * a framework 400 that named no field when it was omitted.
 */
@AutoConfigureWebTestClient
class PinAndRuleDiagnosabilityIT extends AbstractAuthIT {

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
	void pinsListEveryIdentityWhenNoneIsNamedAndFilterWhenOneIs() {
		String token = tokenWith("svc-pins-" + unique(), PlatformPermissions.USER_MANAGE);
		String alice = "alice-" + unique();
		String bob = "bob-" + unique();
		createPin(token, alice);
		createPin(token, bob);

		// The unfiltered form is what offboarding and incident review need: a pin
		// authenticates on its own and outlives its session, so one nobody has
		// accounted for is standing access. Asserting it spans MORE THAN ONE identity
		// is the assertion — a single-identity result would also pass a weaker check.
		List<String> everyone = pinIdentities(token, "/v1/pins");
		assertThat(everyone).contains(alice, bob);

		assertThat(pinIdentities(token, "/v1/pins?identity=" + alice)).containsExactly(alice);
	}

	@Test
	void aDenyRuleNeedsNoTtlAndAnAllowWithoutOneIsRefusedByName() {
		String token = tokenWith("svc-rules-" + unique(), PlatformPermissions.RBAC_WRITE,
				PlatformPermissions.RBAC_READ);

		// A deny grants nothing, so it has no lifetime to bound.
		client.post().uri("/v1/rules").header("Authorization", "Bearer " + token)
				.contentType(MediaType.APPLICATION_JSON).bodyValue(rule("deny-" + unique(), "deny", null)).exchange()
				.expectStatus().isCreated().expectBody().jsonPath("$.ttlSeconds").doesNotExist().jsonPath("$.id")
				.isNotEmpty();

		// A value sent on a deny is stored and echoed back unchanged: "ignored" is what
		// the evaluator does with it, not a licence to rewrite a caller's field — and
		// nulling it would silently drop the value on the next update of every deny
		// rule that carries one today, because the column used to demand one.
		client.post().uri("/v1/rules").header("Authorization", "Bearer " + token)
				.contentType(MediaType.APPLICATION_JSON).bodyValue(rule("deny2-" + unique(), "deny", 3600)).exchange()
				.expectStatus().isCreated().expectBody().jsonPath("$.ttlSeconds").isEqualTo(3600);

		// A present-but-nonsensical value is a named 422 rather than an unmapped
		// integrity failure against the column's own CHECK.
		client.post().uri("/v1/rules").header("Authorization", "Bearer " + token)
				.contentType(MediaType.APPLICATION_JSON).bodyValue(rule("deny3-" + unique(), "deny", 0)).exchange()
				.expectStatus().isEqualTo(422).expectBody().jsonPath("$.detail")
				.value(detail -> assertThat((String) detail).contains("ttlSeconds"));

		// An allow still bounds its grant, and omitting it NAMES the field — the whole
		// point, since the failure this replaces was a bare 400 naming nothing.
		client.post().uri("/v1/rules").header("Authorization", "Bearer " + token)
				.contentType(MediaType.APPLICATION_JSON).bodyValue(rule("allow-" + unique(), "allow", null)).exchange()
				.expectStatus().isEqualTo(422).expectHeader()
				.contentTypeCompatibleWith(MediaType.APPLICATION_PROBLEM_JSON).expectBody().jsonPath("$.detail")
				.value(detail -> assertThat((String) detail).contains("ttlSeconds"));

		client.post().uri("/v1/rules").header("Authorization", "Bearer " + token)
				.contentType(MediaType.APPLICATION_JSON).bodyValue(rule("allow2-" + unique(), "allow", 3600)).exchange()
				.expectStatus().isCreated().expectBody().jsonPath("$.ttlSeconds").isEqualTo(3600);
	}

	@Test
	void aFrameworkBindingFailureIsAProblemDocumentThatNamesTheField() {
		String token = tokenWith("svc-bind-" + unique(), PlatformPermissions.RBAC_WRITE);

		// principals is required by the schema, so this fails inside Spring's binding
		// before any handler runs. It used to answer with the framework default —
		// timestamp/path/status/error/requestId — naming nothing.
		client.post().uri("/v1/rules").header("Authorization", "Bearer " + token)
				.contentType(MediaType.APPLICATION_JSON)
				.bodyValue(Map.of("name", "bind-" + unique(), "identitySelector", Map.of("identities", List.of("x")),
						"nodeLabelSelector", Map.of(), "effect", "deny"))
				.exchange().expectStatus().isBadRequest().expectHeader()
				.contentTypeCompatibleWith(MediaType.APPLICATION_PROBLEM_JSON).expectBody().jsonPath("$.type")
				.value(type -> assertThat((String) type).contains("problems/")).jsonPath("$.detail")
				.value(detail -> assertThat((String) detail).contains("principals"));
	}

	private Map<String, Object> rule(String name, String effect, Integer ttlSeconds) {
		Map<String, Object> body = new java.util.LinkedHashMap<>();
		body.put("name", name);
		body.put("identitySelector", Map.of("identities", List.of("someone")));
		body.put("nodeLabelSelector", Map.of());
		body.put("principals", List.of("deploy"));
		body.put("effect", effect);
		if (ttlSeconds != null) {
			body.put("ttlSeconds", ttlSeconds);
		}
		return body;
	}

	private void createPin(String token, String identity) {
		client.post().uri("/v1/pins").header("Authorization", "Bearer " + token).contentType(MediaType.APPLICATION_JSON)
				.bodyValue(Map.of("fingerprint", "SHA256:" + UUID.randomUUID(), "identity", identity, "principals",
						List.of("deploy"), "ttlSeconds", 3600))
				.exchange().expectStatus().isCreated();
	}

	@SuppressWarnings("unchecked")
	private List<String> pinIdentities(String token, String uri) {
		Map<?, ?> body = client.get().uri(uri).header("Authorization", "Bearer " + token).exchange().expectStatus()
				.isOk().expectBody(Map.class).returnResult().getResponseBody();
		List<Map<String, Object>> pins = (List<Map<String, Object>>) body.get("pins");
		return pins.stream().map(pin -> (String) pin.get("identity")).toList();
	}

	private String tokenWith(String saName, String... permissions) {
		ServiceAccount sa = serviceAccounts
				.save(ServiceAccount.create(saName, "test", "client_secret", null, null, "api")).block();
		var issued = machineIdentity.issueCredential(sa.id(), "client_secret", null, null, null, null, "admin").block();
		if (permissions.length > 0) {
			PlatformRole role = roles.save(
					PlatformRole.create("diag-role-" + UUID.randomUUID(), List.of(permissions), "test", "default"))
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
