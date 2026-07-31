package io.sessionlayer.controlplane.ca.mtls;

import io.sessionlayer.controlplane.mtls.CertificateFingerprints;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Base64;
import org.springframework.r2dbc.core.DatabaseClient;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

/**
 * Exports the active internal mTLS CA certificate — the trust anchor a Gateway
 * pins (Design §2A, §15; FR-CA-3). Public material only.
 *
 * <p>
 * This deliberately does NOT go through {@link InternalMtlsCaService}: loading
 * a backend unwraps the KEK-wrapped private key, which an export of public
 * material has no business doing. The projection below selects
 * {@code ca_certificate} and nothing else, so "no sibling column is read" is
 * provable from the SQL — {@code wrapped_key}, {@code iv} and
 * {@code kek_reference} are never in the result set.
 */
@Service
public class MtlsTrustAnchorService {

	private static final String ACTIVE_ANCHOR_SQL = """
			SELECT k.ca_certificate AS ca_certificate
			FROM runtime.ca_key_material k
			JOIN config.ca_config c ON c.id = k.ca_config_id
			WHERE c.ca_kind = :caKind AND c.rotation_state = 'active' AND k.ca_certificate IS NOT NULL""";

	private final DatabaseClient db;

	public MtlsTrustAnchorService(DatabaseClient db) {
		this.db = db;
	}

	public record TrustAnchor(String pem, String fingerprintSha256, String subject, Instant notBefore,
			Instant notAfter) {
	}

	public Mono<TrustAnchor> activeTrustAnchor() {
		return db.sql(ACTIVE_ANCHOR_SQL).bind("caKind", InternalMtlsCaFactory.CA_KIND)
				.map(row -> row.get("ca_certificate", byte[].class)).one()
				.switchIfEmpty(Mono
						.error(new InternalMtlsCaService.NoMtlsCaAvailable("no active internal mTLS CA certificate")))
				.map(MtlsTrustAnchorService::describe);
	}

	private static TrustAnchor describe(byte[] der) {
		X509Certificate certificate = parse(der);
		return new TrustAnchor(pem(der), CertificateFingerprints.sha256Hex(certificate),
				certificate.getSubjectX500Principal().getName(), certificate.getNotBefore().toInstant(),
				certificate.getNotAfter().toInstant());
	}

	private static X509Certificate parse(byte[] der) {
		try {
			return (X509Certificate) CertificateFactory.getInstance("X.509")
					.generateCertificate(new ByteArrayInputStream(der));
		} catch (Exception malformed) {
			throw new IllegalStateException("stored internal mTLS CA certificate is not a parseable X.509", malformed);
		}
	}

	private static String pem(byte[] der) {
		String body = Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.US_ASCII)).encodeToString(der);
		return "-----BEGIN CERTIFICATE-----\n" + body + "\n-----END CERTIFICATE-----\n";
	}
}
