package io.sessionlayer.controlplane.web;

import static org.assertj.core.api.Assertions.assertThat;

import io.sessionlayer.controlplane.api.model.CaPublicKey;
import io.sessionlayer.controlplane.ca.CaProvisioningService;
import io.sessionlayer.controlplane.ca.key.SshEcdsaPublicKeys;
import io.sessionlayer.controlplane.platform.PlatformPermissions;
import io.sessionlayer.controlplane.support.AbstractConfigApiIT;
import java.security.interfaces.ECPublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.r2dbc.core.DatabaseClient;

class CaPublicKeyExportIT extends AbstractConfigApiIT {

	@Autowired
	private CaProvisioningService provisioning;
	@Autowired
	private DatabaseClient db;

	@BeforeEach
	void provisionCas() {
		provisioning.provisionAll().block();
	}

	@ParameterizedTest
	@ValueSource(strings = {"session", "user", "host"})
	void exportsEachSshKindAsSpkiAndAnOpenSshLine(String caKind) throws Exception {
		String bearer = tokenWith("svc-cak-" + UUID.randomUUID(), PlatformPermissions.NODE_ENROLL);

		CaPublicKey exported = client.get().uri("/v1/cas/" + caKind + "/public-key")
				.header("Authorization", "Bearer " + bearer).exchange().expectStatus().isOk()
				.expectBody(CaPublicKey.class).returnResult().getResponseBody();

		assertThat(exported.getCaKind().getValue()).isEqualTo(caKind);
		assertThat(exported.getRotationState().getValue()).isEqualTo("active");
		assertThat(exported.getOpensshPublicKey()).startsWith("ecdsa-sha2-nistp256 AAAA");
		assertThat(exported.getFingerprint()).startsWith("SHA256:");

		byte[] spki = Base64.getDecoder().decode(exported.getPublicKeySpkiDer());
		ECPublicKey fromSpki = (ECPublicKey) java.security.KeyFactory.getInstance("EC")
				.generatePublic(new X509EncodedKeySpec(spki));
		ECPublicKey fromLine = SshEcdsaPublicKeys.parseAuthorizedKey(exported.getOpensshPublicKey());
		assertThat(fromLine.getW()).isEqualTo(fromSpki.getW());

		byte[] wire = Base64.getDecoder().decode(exported.getOpensshPublicKey().split("\\s+")[1]);
		assertThat(exported.getFingerprint()).isEqualTo(SshEcdsaPublicKeys.fingerprint(wire));

		// The exported SPKI is byte-identical to the stored column, so the projection
		// is provably reading public_key and not deriving it through a backend unwrap.
		byte[] stored = db
				.sql("SELECT k.public_key AS pk FROM runtime.ca_key_material k"
						+ " JOIN config.ca_config c ON c.id = k.ca_config_id"
						+ " WHERE c.ca_kind = :kind AND c.rotation_state = 'active'")
				.bind("kind", caKind).map(row -> row.get("pk", byte[].class)).one().block();
		assertThat(spki).isEqualTo(stored);
	}

	@Test
	void theResponseCarriesNoPrivateOrWrappedMaterial() {
		String bearer = tokenWith("svc-cak-safe-" + UUID.randomUUID(), PlatformPermissions.NODE_ENROLL);

		String raw = client.get().uri("/v1/cas/session/public-key").header("Authorization", "Bearer " + bearer)
				.exchange().expectStatus().isOk().expectBody(String.class).returnResult().getResponseBody();

		assertThat(raw).doesNotContain("PRIVATE KEY").doesNotContain("wrappedKey").doesNotContain("wrapped_key")
				.doesNotContain("kekReference").doesNotContain("privateKey").doesNotContain("keyReference");
	}

	// The internal mTLS CA is not a member of this collection — it has its own
	// trust-anchor sibling — so `mtls` is refused by the closed CaKind enum at
	// parameter binding, before any handler runs.
	@Test
	void theInternalMtlsCaIsNotAddressableHere() {
		String bearer = tokenWith("svc-cak-mtls-" + UUID.randomUUID(), PlatformPermissions.NODE_ENROLL);

		client.get().uri("/v1/cas/mtls/public-key").header("Authorization", "Bearer " + bearer).exchange()
				.expectStatus().isBadRequest();
	}

	/**
	 * The export takes its key type from {@code ca_key_material.key_type}, which
	 * sits alongside the write-once bytes it describes, and never from
	 * {@code ca_config.algorithm}, which {@code PUT /v1/cas/{id}} rewrites in place
	 * without re-keying. So the two CAN diverge, and when they do the export must
	 * follow the key rather than the label — labelling P-256 bytes with a later
	 * {@code nistp521} emits a well-formed authorized-key line for a key that does
	 * not exist, which every node then rejects at session time with nothing
	 * pointing back here.
	 *
	 * <p>
	 * The assertion is INVARIANCE rather than a rejection: divergence is
	 * structurally unexpressible in the response because {@code c.algorithm} is not
	 * in the projection at all, so there is nothing to refuse. This is the test
	 * that fails if anyone re-adds that column.
	 */
	@Test
	void theExportFollowsTheStoredKeyWhenTheConfigAlgorithmDivergesFromIt() {
		String bearer = tokenWith("svc-cak-diverge-" + UUID.randomUUID(), PlatformPermissions.NODE_ENROLL);
		CaPublicKey before = export(bearer);

		try {
			// Behind the API, exactly as PUT /v1/cas/{id} would leave it. Asserting the
			// row count matters: an UPDATE that matched nothing would leave this test
			// passing while proving nothing at all.
			Long diverged = db.sql("UPDATE config.ca_config SET algorithm = 'ecdsa-p521'"
					+ " WHERE ca_kind = 'session' AND rotation_state = 'active'").fetch().rowsUpdated().block();
			assertThat(diverged).isEqualTo(1L);

			CaPublicKey after = export(bearer);

			assertThat(after.getAlgorithm()).isEqualTo(before.getAlgorithm());
			assertThat(after.getOpensshPublicKey()).isEqualTo(before.getOpensshPublicKey());
			assertThat(after.getFingerprint()).isEqualTo(before.getFingerprint());
			assertThat(after.getPublicKeySpkiDer()).isEqualTo(before.getPublicKeySpkiDer());

			// Positively, not just unchanged: it still reports the key that is stored.
			assertThat(after.getAlgorithm().getValue()).isEqualTo("ecdsa-p256");
			assertThat(after.getOpensshPublicKey()).startsWith("ecdsa-sha2-nistp256 AAAA");
		} finally {
			db.sql("UPDATE config.ca_config SET algorithm = 'ecdsa-p256'"
					+ " WHERE ca_kind = 'session' AND rotation_state = 'active'").fetch().rowsUpdated().block();
		}
	}

	private CaPublicKey export(String bearer) {
		return client.get().uri("/v1/cas/session/public-key").header("Authorization", "Bearer " + bearer).exchange()
				.expectStatus().isOk().expectBody(CaPublicKey.class).returnResult().getResponseBody();
	}

	@Test
	void theExportNeedsNodeEnroll() {
		String noPermission = tokenWith("svc-cak-none-" + UUID.randomUUID());
		String caManage = tokenWith("svc-cak-ca-" + UUID.randomUUID(), PlatformPermissions.CA_MANAGE);

		client.get().uri("/v1/cas/session/public-key").header("Authorization", "Bearer " + noPermission).exchange()
				.expectStatus().isForbidden();
		// ca:manage administers CAs; it is deliberately not what installing a node
		// requires, and it does not stand in for node:enroll here.
		client.get().uri("/v1/cas/session/public-key").header("Authorization", "Bearer " + caManage).exchange()
				.expectStatus().isForbidden();
	}
}
