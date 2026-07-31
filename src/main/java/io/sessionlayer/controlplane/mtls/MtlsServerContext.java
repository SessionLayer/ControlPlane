package io.sessionlayer.controlplane.mtls;

import io.grpc.netty.GrpcSslContexts;
import io.netty.handler.ssl.ClientAuth;
import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslContextBuilder;
import io.netty.handler.ssl.SslProvider;
import io.sessionlayer.controlplane.ca.mtls.LeafCertificateSpec;
import io.sessionlayer.controlplane.ca.mtls.LeafPurpose;
import io.sessionlayer.controlplane.ca.mtls.X509CaBackend;
import io.sessionlayer.controlplane.ca.mtls.X509Certificates;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import javax.net.ssl.X509TrustManager;

/**
 * TLS material for CP's self-managed mTLS gRPC server (TLS 1.3, ephemeral
 * server key, internal CA trust, PKIX re-validation via
 * {@code AuthInterceptor}).
 */
public record MtlsServerContext(SslContext sslContext, X509Certificate caCertificate, X509TrustManager trustManager) {

	/**
	 * Server cert lifetime (re-minted on restart, independent of Gateway
	 * identity-cert TTL).
	 */
	private static final Duration SERVER_CERT_TTL = Duration.ofDays(365);

	private static final SecureRandom RANDOM = new SecureRandom();

	/**
	 * {@code hostnames} become DNS SANs (first is CN).
	 */
	public static MtlsServerContext create(X509CaBackend backend, List<String> hostnames, Duration backdate) {
		if (hostnames == null || hostnames.isEmpty()) {
			throw new IllegalArgumentException("at least one server hostname (SAN) is required");
		}
		try {
			KeyPair serverKey = generateKeyPair();
			Instant now = Instant.now();
			X509Certificate serverCert = backend
					.issueLeaf(new LeafCertificateSpec(serverKey.getPublic(), hostnames.get(0), hostnames, List.of(),
							LeafPurpose.SERVER, newSerial(), now.minus(backdate), now.plus(SERVER_CERT_TTL)));
			X509Certificate caCertificate = backend.caCertificate();
			SslContextBuilder builder = SslContextBuilder.forServer(serverKey.getPrivate(), serverCert)
					.trustManager(caCertificate).clientAuth(ClientAuth.OPTIONAL);
			GrpcSslContexts.configure(builder, SslProvider.JDK);
			builder.protocols("TLSv1.3"); // TLS 1.3 only (VERSIONING.md §7)
			SslContext sslContext = builder.build();
			X509TrustManager trustManager = X509Certificates.trustManagerFor(caCertificate);
			return new MtlsServerContext(sslContext, caCertificate, trustManager);
		} catch (Exception e) {
			throw new IllegalStateException("failed to build the mTLS server context", e);
		}
	}

	private static KeyPair generateKeyPair() throws Exception {
		KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
		generator.initialize(new ECGenParameterSpec("secp256r1"), RANDOM);
		return generator.generateKeyPair();
	}

	private static BigInteger newSerial() {
		return new BigInteger(159, RANDOM).add(BigInteger.ONE);
	}
}
