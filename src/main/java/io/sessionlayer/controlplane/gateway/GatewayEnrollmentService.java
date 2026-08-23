package io.sessionlayer.controlplane.gateway;

import io.sessionlayer.controlplane.audit.AuditEventStore;
import io.sessionlayer.controlplane.ca.mtls.InternalMtlsCaService;
import io.sessionlayer.controlplane.ca.mtls.LeafCertificateSpec;
import io.sessionlayer.controlplane.ca.mtls.LeafPurpose;
import io.sessionlayer.controlplane.ca.mtls.Pkcs10Csrs;
import io.sessionlayer.controlplane.ca.mtls.X509CaBackend;
import io.sessionlayer.controlplane.data.Uuids;
import io.sessionlayer.controlplane.data.runtime.GatewayIdentity;
import io.sessionlayer.controlplane.data.runtime.GatewayIdentityRepository;
import io.sessionlayer.controlplane.mtls.CertificateFingerprints;
import io.sessionlayer.controlplane.mtls.GatewayIdentityUri;
import io.sessionlayer.controlplane.mtls.MtlsProperties;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

@Service
public class GatewayEnrollmentService {

	private final GatewayEnrollmentTokenService tokenService;
	private final InternalMtlsCaService mtlsCa;
	private final GatewayIdentityRepository gatewayIdentities;
	private final MtlsProperties properties;
	private final AuditEventStore audit;

	public GatewayEnrollmentService(GatewayEnrollmentTokenService tokenService, InternalMtlsCaService mtlsCa,
			GatewayIdentityRepository gatewayIdentities, MtlsProperties properties, AuditEventStore audit) {
		this.tokenService = tokenService;
		this.mtlsCa = mtlsCa;
		this.gatewayIdentities = gatewayIdentities;
		this.properties = properties;
		this.audit = audit;
	}

	public Mono<IssuedIdentity> enroll(String rawToken, byte[] csrDer, String gatewayName) {
		// Also enforced at mint; repeated here so a token minted before this rule
		// existed (or straight into the table via psql) still cannot enroll.
		if (!GatewayNames.isEnrollable(gatewayName, properties.getServer().getHostnames())) {
			return Mono.error(new GatewayRequestException(GatewayRequestException.Reason.INVALID_ARGUMENT,
					"invalid gateway_name"));
		}
		return Mono.zip(tokenService.isValid(rawToken, gatewayName),
				gatewayIdentities.findByName(gatewayName).hasElement()).flatMap(state -> {
					boolean tokenValid = state.getT1();
					boolean alreadyEnrolled = state.getT2();
					if (!tokenValid || alreadyEnrolled) {
						String reason = tokenValid ? "already_enrolled" : "invalid_or_expired_token";
						return audit.record(gatewayName, gatewayName, "gateway.enroll", "denied", null, null,
								Map.of("reason", reason)).then(Mono.error(enrollmentRefused()));
					}
					return Mono.fromCallable(() -> parseCsr(csrDer, gatewayName))
							.subscribeOn(Schedulers.boundedElastic())
							.flatMap(csr -> tokenService.consume(rawToken, gatewayName).then(issue(gatewayName, csr)));
				});
	}

	private Mono<IssuedIdentity> issue(String gatewayName, Pkcs10Csrs.ParsedCsr csr) {
		return mtlsCa.activeBackend().flatMap(backend -> {
			UUID gatewayId = Uuids.v7();
			Instant now = Instant.now();
			Instant notBefore = now.minus(properties.getCertBackdate());
			Instant notAfter = now.plus(properties.getIdentityCertTtl());
			return Mono
					.fromCallable(() -> backend.issueLeaf(new LeafCertificateSpec(csr.publicKey(), gatewayName,
							List.of(gatewayName), List.of(GatewayIdentityUri.of(gatewayId)), LeafPurpose.CLIENT,
							serial(Uuids.v7()), notBefore, notAfter)))
					.subscribeOn(Schedulers.boundedElastic()).flatMap(leaf -> {
						String fingerprint = CertificateFingerprints.sha256Hex(leaf);
						GatewayIdentity identity = new GatewayIdentity(gatewayId, gatewayName, "mtls:" + gatewayId,
								fingerprint, null, 0L, "token", "active", notBefore, notAfter, null, null, null, null,
								null, null);
						return gatewayIdentities.save(identity)
								.then(audit.record(gatewayName, gatewayName, "gateway.enroll", "success", null, null,
										Map.of("generation", "0", "fingerprint", fingerprint)))
								.thenReturn(toIssued(leaf, backend, gatewayId, 0L, notBefore, notAfter));
					});
		});
	}

	private static GatewayRequestException enrollmentRefused() {
		return new GatewayRequestException(GatewayRequestException.Reason.UNAUTHENTICATED, "enrollment refused");
	}

	private static Pkcs10Csrs.ParsedCsr parseCsr(byte[] csrDer, String gatewayName) {
		Pkcs10Csrs.ParsedCsr csr;
		try {
			csr = Pkcs10Csrs.parseAndVerify(csrDer);
		} catch (Pkcs10Csrs.CsrException e) {
			throw new GatewayRequestException(GatewayRequestException.Reason.INVALID_ARGUMENT, "invalid CSR");
		}
		if (!gatewayName.equals(csr.commonName())) {
			throw new GatewayRequestException(GatewayRequestException.Reason.INVALID_ARGUMENT,
					"CSR subject does not match gateway_name");
		}
		return csr;
	}

	static IssuedIdentity toIssued(X509Certificate leaf, X509CaBackend backend, UUID gatewayId, long generation,
			Instant notBefore, Instant notAfter) {
		return new IssuedIdentity(der(leaf), List.of(der(backend.caCertificate())), gatewayId, generation,
				notBefore.getEpochSecond(), notAfter.getEpochSecond());
	}

	static byte[] der(X509Certificate certificate) {
		try {
			return certificate.getEncoded();
		} catch (CertificateEncodingException e) {
			throw new IllegalStateException("failed to encode issued certificate", e);
		}
	}

	static BigInteger serial(UUID id) {
		ByteBuffer buffer = ByteBuffer.allocate(16);
		buffer.putLong(id.getMostSignificantBits()).putLong(id.getLeastSignificantBits());
		BigInteger serial = new BigInteger(1, buffer.array());
		return serial.signum() == 0 ? BigInteger.ONE : serial;
	}
}
