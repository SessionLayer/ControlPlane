package io.sessionlayer.controlplane.web;

import static org.assertj.core.api.Assertions.assertThat;

import io.sessionlayer.controlplane.api.model.CaPage;
import io.sessionlayer.controlplane.api.model.MtlsTrustAnchor;
import io.sessionlayer.controlplane.ca.mtls.InternalMtlsCaService;
import io.sessionlayer.controlplane.ca.mtls.X509Certificates;
import io.sessionlayer.controlplane.data.config.PlatformRole;
import io.sessionlayer.controlplane.data.config.PlatformRoleRepository;
import io.sessionlayer.controlplane.data.config.RoleBinding;
import io.sessionlayer.controlplane.data.config.RoleBindingRepository;
import io.sessionlayer.controlplane.data.config.ServiceAccount;
import io.sessionlayer.controlplane.data.config.ServiceAccountRepository;
import io.sessionlayer.controlplane.machine.MachineIdentityService;
import io.sessionlayer.controlplane.mtls.CertificateFingerprints;
import io.sessionlayer.controlplane.platform.PlatformPermissions;
import io.sessionlayer.controlplane.support.AbstractAuthIT;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webtestclient.autoconfigure.AutoConfigureWebTestClient;
import org.springframework.test.web.reactive.server.WebTestClient;

@AutoConfigureWebTestClient
class MtlsTrustAnchorIT extends AbstractAuthIT {

	@Autowired
	WebTestClient client;
	@Autowired
	InternalMtlsCaService mtlsCa;
	@Autowired
	MachineIdentityService machineIdentity;
	@Autowired
	ServiceAccountRepository serviceAccounts;
	@Autowired
	PlatformRoleRepository roles;
	@Autowired
	RoleBindingRepository bindings;

	@BeforeEach
	void provisionInternalCa() {
		mtlsCa.ensureProvisioned("local").block();
	}

	@Test
	void exportsTheCaCertificateAndNoPrivateKeyMaterial() {
		String bearer = tokenWith("svc-ta-" + UUID.randomUUID(), PlatformPermissions.GATEWAY_ENROLL);

		String body = client.get().uri("/v1/cas/mtls/trust-anchor").header("Authorization", "Bearer " + bearer)
				.exchange().expectStatus().isOk().expectBody(String.class).returnResult().getResponseBody();

		// Assert on the serialized body: private material would be a stray property no
		// typed getter would surface.
		assertThat(body).doesNotContain("PRIVATE KEY").doesNotContain("wrappedKey").doesNotContain("wrapped_key")
				.doesNotContain("kekReference").doesNotContain("privateKey").contains("BEGIN CERTIFICATE");

		MtlsTrustAnchor anchor = client.get().uri("/v1/cas/mtls/trust-anchor")
				.header("Authorization", "Bearer " + bearer).exchange().expectStatus().isOk()
				.expectBody(MtlsTrustAnchor.class).returnResult().getResponseBody();

		// The PEM must be a parseable X.509 whose public key is the CA's - the load
		// -bearing proof that ca_certificate, not a sibling column, was read.
		X509Certificate exported = X509Certificates.parse(der(anchor.getPem()));
		X509Certificate actual = mtlsCa.activeBackend().block().caCertificate();
		assertThat(exported.getPublicKey()).isEqualTo(actual.getPublicKey());
		assertThat(exported).isEqualTo(actual);
		assertThat(exported.getBasicConstraints()).isNotNegative();

		assertThat(anchor.getFingerprintSha256()).isEqualTo(CertificateFingerprints.sha256Hex(actual))
				.matches("[0-9a-f]{64}");
		assertThat(anchor.getSubject()).isEqualTo(actual.getSubjectX500Principal().getName());
		assertThat(anchor.getNotBefore().toInstant()).isEqualTo(actual.getNotBefore().toInstant());
		assertThat(anchor.getNotAfter().toInstant()).isEqualTo(actual.getNotAfter().toInstant());
	}

	@Test
	void theInternalCaStaysOutOfTheCasCollection() {
		String bearer = tokenWith("svc-ta-cas-" + UUID.randomUUID(), PlatformPermissions.CA_MANAGE);

		CaPage page = client.get().uri("/v1/cas").header("Authorization", "Bearer " + bearer).exchange().expectStatus()
				.isOk().expectBody(CaPage.class).returnResult().getResponseBody();

		assertThat(page.getItems()).noneSatisfy(ca -> assertThat(ca.getCaKind().getValue()).isEqualTo("mtls"));
	}

	private static byte[] der(String pem) {
		String base64 = pem.replace("-----BEGIN CERTIFICATE-----", "").replace("-----END CERTIFICATE-----", "")
				.replaceAll("\\s", "");
		return Base64.getDecoder().decode(base64);
	}

	private String tokenWith(String saName, String... permissions) {
		ServiceAccount sa = serviceAccounts
				.save(ServiceAccount.create(saName, "test", "client_secret", null, null, "api")).block();
		var issued = machineIdentity.issueCredential(sa.id(), "client_secret", null, null, null, null, "admin").block();
		if (permissions.length > 0) {
			PlatformRole role = roles
					.save(PlatformRole.create("ta-role-" + UUID.randomUUID(), List.of(permissions), "test", "default"))
					.block();
			bindings.save(RoleBinding.create(role.id(), "user", saName, null, "default")).block();
		}
		var token = machineIdentity.issueToken(new MachineIdentityService.TokenRequest("client_credentials", saName,
				null, null, issued.clientSecret(), null), null, "203.0.113.32").block();
		return token.accessToken();
	}
}
