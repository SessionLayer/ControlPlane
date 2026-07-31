package io.sessionlayer.controlplane.mtls;

import com.google.protobuf.ByteString;
import io.grpc.ManagedChannel;
import io.netty.handler.ssl.SslContext;
import io.sessionlayer.controlplane.ca.mtls.InternalMtlsCaService;
import io.sessionlayer.controlplane.ca.mtls.LeafCertificateSpec;
import io.sessionlayer.controlplane.ca.mtls.LeafPurpose;
import io.sessionlayer.controlplane.ca.mtls.X509CaBackend;
import io.sessionlayer.controlplane.ca.mtls.X509Certificates;
import io.sessionlayer.controlplane.data.runtime.GatewayIdentityRepository;
import io.sessionlayer.controlplane.gateway.GatewayEnrollmentTokenService;
import io.sessionlayer.controlplane.gateway.SessionSigningTokenService;
import io.sessionlayer.controlplane.grpc.v1.EnrollGatewayRequest;
import io.sessionlayer.controlplane.grpc.v1.EnrollGatewayResponse;
import io.sessionlayer.controlplane.grpc.v1.GatewayIdentityGrpc;
import io.sessionlayer.controlplane.grpc.v1.PresenceGrpc;
import io.sessionlayer.controlplane.grpc.v1.PresenceHeartbeatRequest;
import io.sessionlayer.controlplane.grpc.v1.PresenceHeartbeatResponse;
import io.sessionlayer.controlplane.grpc.v1.PresenceReleaseRequest;
import io.sessionlayer.controlplane.grpc.v1.PresenceReleaseResponse;
import io.sessionlayer.controlplane.grpc.v1.SessionSigningGrpc;
import io.sessionlayer.controlplane.grpc.v1.SignContext;
import io.sessionlayer.controlplane.grpc.v1.SignSessionCertificateRequest;
import io.sessionlayer.controlplane.grpc.v1.SignSessionCertificateResponse;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.TimeUnit;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.r2dbc.core.DatabaseClient;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.postgresql.PostgreSQLContainer;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.NONE, properties = "sessionlayer.mtls.server.port=0")
abstract class AbstractMtlsIT {

	@SuppressWarnings("resource") // shared singleton; stopped by Ryuk at JVM exit
	static final PostgreSQLContainer POSTGRES = new PostgreSQLContainer("postgres:17-alpine")
			.withDatabaseName("sessionlayer").withUsername("sessionlayer").withPassword("sessionlayer");

	static {
		POSTGRES.start();
	}

	@DynamicPropertySource
	static void properties(DynamicPropertyRegistry registry) {
		registry.add("spring.r2dbc.url", () -> String.format("r2dbc:postgresql://%s:%d/%s", POSTGRES.getHost(),
				POSTGRES.getMappedPort(PostgreSQLContainer.POSTGRESQL_PORT), POSTGRES.getDatabaseName()));
		registry.add("spring.r2dbc.username", () -> "cp_runtime");
		registry.add("spring.r2dbc.password", () -> "cp_runtime");
		registry.add("spring.flyway.url", POSTGRES::getJdbcUrl);
		registry.add("spring.flyway.user", POSTGRES::getUsername);
		registry.add("spring.flyway.password", POSTGRES::getPassword);
		registry.add("spring.flyway.placeholders.cpRuntimePassword", () -> "cp_runtime");
		registry.add("sessionlayer.ca.local.allow-dev-kek", () -> "true");
		registry.add("sessionlayer.audit.partition-maintenance.enabled", () -> "false");
	}

	@Autowired
	protected GrpcMtlsServer grpcServer;
	@Autowired
	protected InternalMtlsCaService mtlsCa;
	@Autowired
	protected GatewayEnrollmentTokenService enrollmentTokens;
	@Autowired
	protected SessionSigningTokenService signingTokens;
	@Autowired
	protected GatewayIdentityRepository gatewayIdentities;
	@Autowired
	protected DatabaseClient db;

	protected record EnrolledGateway(UUID gatewayId, KeyPair keyPair, X509Certificate certificate, long generation) {
	}

	protected int grpcPort() {
		return grpcServer.getPort();
	}

	protected X509Certificate caCertificate() {
		return mtlsCa.activeBackend().block().caCertificate();
	}

	protected EnrolledGateway enroll(String gatewayName) {
		String token = enrollmentTokens.mint(gatewayName, "test-operator").block();
		return enrollWithToken(gatewayName, token);
	}

	protected EnrolledGateway enrollWithToken(String gatewayName, String rawToken) {
		KeyPair keyPair = MtlsTestSupport.generateEcKeyPair();
		byte[] csr = MtlsTestSupport.csr(keyPair, gatewayName);
		ManagedChannel channel = MtlsTestSupport.channel(grpcPort(),
				MtlsTestSupport.clientSslContext(caCertificate(), null, null));
		try {
			EnrollGatewayResponse response = GatewayIdentityGrpc.newBlockingStub(channel)
					.enrollGateway(EnrollGatewayRequest.newBuilder().setEnrollmentToken(rawToken)
							.setPkcs10Csr(ByteString.copyFrom(csr)).setGatewayName(gatewayName).build());
			X509Certificate leaf = X509Certificates.parse(response.getCertificate().toByteArray());
			return new EnrolledGateway(UUID.fromString(response.getGatewayId()), keyPair, leaf,
					response.getGeneration());
		} finally {
			shutdown(channel);
		}
	}

	protected X509Certificate mintClientCert(PublicKey publicKey, UUID gatewayId, Instant notBefore, Instant notAfter) {
		X509CaBackend backend = mtlsCa.activeBackend().block();
		List<String> uriSans = (gatewayId == null) ? List.of() : List.of(GatewayIdentityUri.of(gatewayId));
		return backend.issueLeaf(new LeafCertificateSpec(publicKey, "probe-gateway", List.of("probe-gateway"), uriSans,
				LeafPurpose.CLIENT, BigInteger.valueOf(System.nanoTime()), notBefore, notAfter));
	}

	protected SignSessionCertificateResponse signSessionCertificate(EnrolledGateway gateway, String rawToken,
			byte[] subjectPublicKeyBlob, SignContext context) {
		SslContext ssl = MtlsTestSupport.clientSslContext(caCertificate(), gateway.certificate(),
				gateway.keyPair().getPrivate());
		ManagedChannel channel = MtlsTestSupport.channel(grpcPort(), ssl);
		try {
			SignSessionCertificateRequest.Builder request = SignSessionCertificateRequest.newBuilder()
					.setSessionToken(rawToken).setSubjectPublicKey(ByteString.copyFrom(subjectPublicKeyBlob));
			if (context != null) {
				request.setContext(context);
			}
			return SessionSigningGrpc.newBlockingStub(channel).signSessionCertificate(request.build());
		} finally {
			shutdown(channel);
		}
	}

	protected PresenceHeartbeatResponse presenceHeartbeat(EnrolledGateway gateway, String nodeName,
			String gatewayAddr) {
		SslContext ssl = MtlsTestSupport.clientSslContext(caCertificate(), gateway.certificate(),
				gateway.keyPair().getPrivate());
		ManagedChannel channel = MtlsTestSupport.channel(grpcPort(), ssl);
		try {
			return PresenceGrpc.newBlockingStub(channel).heartbeat(
					PresenceHeartbeatRequest.newBuilder().setNodeName(nodeName).setGatewayAddr(gatewayAddr).build());
		} finally {
			shutdown(channel);
		}
	}

	protected PresenceReleaseResponse presenceRelease(EnrolledGateway gateway, String nodeName) {
		SslContext ssl = MtlsTestSupport.clientSslContext(caCertificate(), gateway.certificate(),
				gateway.keyPair().getPrivate());
		ManagedChannel channel = MtlsTestSupport.channel(grpcPort(), ssl);
		try {
			return PresenceGrpc.newBlockingStub(channel)
					.release(PresenceReleaseRequest.newBuilder().setNodeName(nodeName).build());
		} finally {
			shutdown(channel);
		}
	}

	protected static void shutdown(ManagedChannel channel) {
		try {
			channel.shutdownNow().awaitTermination(5, TimeUnit.SECONDS);
		} catch (InterruptedException e) {
			Thread.currentThread().interrupt();
		}
	}
}
