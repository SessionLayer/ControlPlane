package io.sessionlayer.controlplane.ca;

import io.sessionlayer.controlplane.ca.key.SshEcdsaPublicKeys;
import io.sessionlayer.controlplane.web.ApiProblemException;
import io.sessionlayer.controlplane.web.ApiProblemType;
import java.security.KeyFactory;
import java.security.interfaces.ECPublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import org.springframework.r2dbc.core.DatabaseClient;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

/**
 * Exports the active SSH CA's PUBLIC key - the material a node installs into
 * {@code TrustedUserCAKeys}. Public material only.
 *
 * <p>
 * Like the mTLS trust-anchor export, this deliberately does NOT go through the
 * CA backend: loading one unwraps the KEK-wrapped private key, which an export
 * of public material has no business doing. The projection below selects
 * {@code public_key} and three config columns and nothing else, so "no private
 * material is read" is provable from the SQL - {@code wrapped_key}, {@code iv}
 * and {@code kek_reference} are never in the result set.
 */
@Service
public class CaPublicKeyService {

	// key_type comes from ca_key_material, NOT from ca_config.algorithm. The key
	// bytes are write-once; the config column can be updated in place, so the two
	// diverge on any edit and labelling P-256 bytes with the config's later
	// nistp521 emits a well-formed line for the wrong key type. Every node then
	// rejects the certificate at session time with nothing pointing back here.
	private static final String ACTIVE_PUBLIC_KEY_SQL = """
			SELECT k.public_key AS public_key, k.key_type AS key_type, c.name AS name,
			       c.rotation_state AS rotation_state
			FROM runtime.ca_key_material k
			JOIN config.ca_config c ON c.id = k.ca_config_id
			WHERE c.ca_kind = :caKind AND c.rotation_state = 'active'""";

	private final DatabaseClient db;

	public CaPublicKeyService(DatabaseClient db) {
		this.db = db;
	}

	public record ExportedCaPublicKey(String caKind, String algorithm, String rotationState, String publicKeySpkiDer,
			String opensshPublicKey, String fingerprint) {
	}

	public Mono<ExportedCaPublicKey> activePublicKey(String caKind) {
		return db.sql(ACTIVE_PUBLIC_KEY_SQL).bind("caKind", caKind)
				.map(row -> describe(caKind, row.get("public_key", byte[].class), row.get("name", String.class),
						row.get("key_type", String.class), row.get("rotation_state", String.class)))
				.one().switchIfEmpty(Mono.error(
						new ApiProblemException(ApiProblemType.NOT_FOUND, "no active CA of kind '" + caKind + "'")));
	}

	private static ExportedCaPublicKey describe(String caKind, byte[] spkiDer, String name, String storedKeyType,
			String rotationState) {
		CaKeyType keyType = assemblableKeyType(storedKeyType, caKind);
		ECPublicKey publicKey = parse(spkiDer);
		byte[] wire = SshEcdsaPublicKeys.encode(publicKey, keyType);
		return new ExportedCaPublicKey(caKind, keyType.algorithmId(), rotationState,
				Base64.getEncoder().encodeToString(spkiDer),
				SshEcdsaPublicKeys.toAuthorizedKey(publicKey, keyType, name), SshEcdsaPublicKeys.fingerprint(wire));
	}

	// A mislabelled authorized-key line fails at every node, at session time, with
	// no obvious cause - so a key type this Control Plane cannot assemble is
	// refused here rather than emitted under an ECDSA key-type name. Reachable on
	// an upgraded deployment: the CHECK admits algorithms CaKeyType does not
	// implement and is deliberately never narrowed.
	private static CaKeyType assemblableKeyType(String storedKeyType, String caKind) {
		try {
			return CaKeyType.fromKeyTypeName(storedKeyType);
		} catch (IllegalArgumentException unassemblable) {
			throw ApiProblemException.conflict("the active '" + caKind + "' CA's stored key is of type '"
					+ storedKeyType + "', which this Control Plane cannot assemble, so no OpenSSH public key can be "
					+ "exported for it");
		}
	}

	private static ECPublicKey parse(byte[] spkiDer) {
		try {
			return (ECPublicKey) KeyFactory.getInstance("EC").generatePublic(new X509EncodedKeySpec(spkiDer));
		} catch (Exception malformed) {
			throw new IllegalStateException("stored CA public key is not a parseable EC SubjectPublicKeyInfo",
					malformed);
		}
	}
}
