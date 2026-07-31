package io.sessionlayer.controlplane.data;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.charset.StandardCharsets;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.r2dbc.core.DatabaseClient;
import reactor.test.StepVerifier;

/**
 * V30: {@code key_location} ties {@code wrapped_key}/{@code iv}/
 * {@code kek_reference} together as one shape instead of three independent
 * CHECKs. Proves both shapes at the database itself — the app-level factories
 * ({@code CaKeyMaterial.create}/{@code .createExternal}) can only ever build a
 * valid one, so they cannot demonstrate that an invalid one is refused.
 */
class ExternalCaKeyMaterialConstraintIT extends AbstractDataIT {

	private static final byte[] PUBLIC_KEY = "spki-placeholder".getBytes(StandardCharsets.UTF_8);
	private static final byte[] WRAPPED_KEY = "ciphertext-placeholder".getBytes(StandardCharsets.UTF_8);
	private static final byte[] IV_12_BYTES = new byte[12];

	@Autowired
	private DatabaseClient db;

	@Test
	void aFullLocalKekRowIsAcceptedAndDefaultsKeyLocation() {
		UUID id = Uuids.v7();
		// key_location omitted entirely -> proves the DEFAULT 'local_kek', not just
		// that the explicit value is accepted.
		Long rows = db
				.sql("INSERT INTO runtime.ca_key_material "
						+ "(id, ca_config_id, ca_config_name, public_key, kek_reference, wrapped_key, iv) "
						+ "VALUES (:id, :caConfigId, :caConfigName, :publicKey, :kekReference, :wrappedKey, :iv)")
				.bind("id", id).bind("caConfigId", Uuids.v7()).bind("caConfigName", "it-local-" + id)
				.bind("publicKey", PUBLIC_KEY).bind("kekReference", "kek:it").bind("wrappedKey", WRAPPED_KEY)
				.bind("iv", IV_12_BYTES).fetch().rowsUpdated().block();
		assertThat(rows).isEqualTo(1L);

		String keyLocation = db.sql("SELECT key_location FROM runtime.ca_key_material WHERE id = :id").bind("id", id)
				.map(row -> row.get(0, String.class)).one().block();
		assertThat(keyLocation).isEqualTo("local_kek");
	}

	@Test
	void anExternalRowWithAllThreeNullIsAccepted() {
		UUID id = Uuids.v7();
		Long rows = db.sql("INSERT INTO runtime.ca_key_material "
				+ "(id, ca_config_id, ca_config_name, public_key, key_location, kek_reference, wrapped_key, iv) "
				+ "VALUES (:id, :caConfigId, :caConfigName, :publicKey, 'external', NULL, NULL, NULL)").bind("id", id)
				.bind("caConfigId", Uuids.v7()).bind("caConfigName", "it-external-" + id).bind("publicKey", PUBLIC_KEY)
				.fetch().rowsUpdated().block();
		assertThat(rows).isEqualTo(1L);
	}

	@Test
	void anExternalRowCarryingAWrappedKeyIsRejectedByTheDatabase() {
		UUID id = Uuids.v7();
		StepVerifier.create(db.sql("INSERT INTO runtime.ca_key_material "
				+ "(id, ca_config_id, ca_config_name, public_key, key_location, kek_reference, wrapped_key, iv) "
				+ "VALUES (:id, :caConfigId, :caConfigName, :publicKey, 'external', NULL, :wrappedKey, NULL)")
				.bind("id", id).bind("caConfigId", Uuids.v7()).bind("caConfigName", "it-bad-external-" + id)
				.bind("publicKey", PUBLIC_KEY).bind("wrappedKey", WRAPPED_KEY).fetch().rowsUpdated()).verifyError();
	}

	@Test
	void aLocalKekRowMissingItsIvIsRejectedByTheDatabase() {
		UUID id = Uuids.v7();
		StepVerifier.create(db.sql("INSERT INTO runtime.ca_key_material "
				+ "(id, ca_config_id, ca_config_name, public_key, key_location, kek_reference, wrapped_key, iv) "
				+ "VALUES (:id, :caConfigId, :caConfigName, :publicKey, 'local_kek', :kekReference, :wrappedKey, NULL)")
				.bind("id", id).bind("caConfigId", Uuids.v7()).bind("caConfigName", "it-bad-local-" + id)
				.bind("publicKey", PUBLIC_KEY).bind("kekReference", "kek:it").bind("wrappedKey", WRAPPED_KEY).fetch()
				.rowsUpdated()).verifyError();
	}

	@Test
	void anUnknownKeyLocationIsRejectedByTheDatabase() {
		UUID id = Uuids.v7();
		StepVerifier.create(db.sql("INSERT INTO runtime.ca_key_material "
				+ "(id, ca_config_id, ca_config_name, public_key, key_location, kek_reference, wrapped_key, iv) "
				+ "VALUES (:id, :caConfigId, :caConfigName, :publicKey, 'cloud', :kekReference, :wrappedKey, :iv)")
				.bind("id", id).bind("caConfigId", Uuids.v7()).bind("caConfigName", "it-bad-location-" + id)
				.bind("publicKey", PUBLIC_KEY).bind("kekReference", "kek:it").bind("wrappedKey", WRAPPED_KEY)
				.bind("iv", IV_12_BYTES).fetch().rowsUpdated()).verifyError();
	}
}
