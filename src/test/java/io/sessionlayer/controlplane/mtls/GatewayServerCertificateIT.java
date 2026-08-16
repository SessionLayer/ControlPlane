package io.sessionlayer.controlplane.mtls;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.catchThrowableOfType;

import com.google.protobuf.ByteString;
import io.grpc.ManagedChannel;
import io.grpc.Status;
import io.grpc.StatusRuntimeException;
import io.netty.handler.ssl.SslContext;
import io.sessionlayer.controlplane.ca.mtls.LeafCertificateSpec;
import io.sessionlayer.controlplane.ca.mtls.LeafPurpose;
import io.sessionlayer.controlplane.ca.mtls.X509Certificates;
import io.sessionlayer.controlplane.grpc.v1.GatewayIdentityGrpc;
import io.sessionlayer.controlplane.grpc.v1.IssueGatewayServerCertificateRequest;
import io.sessionlayer.controlplane.grpc.v1.IssueGatewayServerCertificateResponse;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Collection;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.Test;

class GatewayServerCertificateIT extends AbstractMtlsIT {

	private static final String SERVER_AUTH = "1.3.6.1.5.5.7.3.1";
	private static final String CLIENT_AUTH = "1.3.6.1.5.5.7.3.2";

	@Test
	void issuesAServerAuthLeafWithCpChosenSansIgnoringAHostileCsr() throws Exception {
		String name = "gw-servercert-" + unique();
		EnrolledGateway gateway = enroll(name);
		KeyPair serverKey = MtlsTestSupport.generateEcKeyPair();
		byte[] hostileCsr = MtlsTestSupport.csrRequestingSans(serverKey, "victim-gateway",
				List.of("victim-gateway", "evil.example.com"));

		IssueGatewayServerCertificateResponse response = issueServerCert(gateway, hostileCsr);

		X509Certificate leaf = X509Certificates.parse(response.getCertificate().toByteArray());
		assertThat(leaf.getExtendedKeyUsage()).containsExactly(SERVER_AUTH);
		assertThat(leaf.getExtendedKeyUsage()).doesNotContain(CLIENT_AUTH);
		assertThat(leaf.getSubjectX500Principal().getName()).isEqualTo("CN=" + name);
		assertThat(dnsSans(leaf)).containsExactly(name);
		assertThat(dnsSans(leaf)).doesNotContain("victim-gateway", "evil.example.com");
		assertThat(uriSans(leaf)).containsExactly(GatewayIdentityUri.of(gateway.gatewayId()));
		assertThat(response.getGatewayName()).isEqualTo(name);
		assertThat(leaf.getPublicKey()).isEqualTo(serverKey.getPublic());
		assertThat(leaf.getPublicKey()).isNotEqualTo(gateway.certificate().getPublicKey());
		assertThat(response.getNotBeforeEpochSeconds()).isLessThan(Instant.now().getEpochSecond());
		assertThat(response.getNotAfterEpochSeconds()).isGreaterThan(Instant.now().getEpochSecond());

		Long audited = db
				.sql("SELECT count(*) FROM runtime.audit_event WHERE action = 'gateway.server_cert.issue' "
						+ "AND outcome = 'success' AND actor = :actor")
				.bind("actor", name).map(row -> row.get(0, Long.class)).one().block();
		assertThat(audited).isEqualTo(1L);
	}

	@Test
	void issuedLeafChainsToTheInternalMtlsCa() throws Exception {
		EnrolledGateway gateway = enroll("gw-servercert-chain-" + unique());
		KeyPair serverKey = MtlsTestSupport.generateEcKeyPair();

		IssueGatewayServerCertificateResponse response = issueServerCert(gateway,
				MtlsTestSupport.csr(serverKey, "tls-server"));

		X509Certificate leaf = X509Certificates.parse(response.getCertificate().toByteArray());
		assertThat(response.getCaChainList()).hasSize(1);
		assertThat(X509Certificates.parse(response.getCaChain(0).toByteArray())).isEqualTo(caCertificate());

		CertPath path = CertificateFactory.getInstance("X.509").generateCertPath(List.of(leaf));
		PKIXParameters params = new PKIXParameters(Set.of(new TrustAnchor(caCertificate(), null)));
		params.setRevocationEnabled(false);
		assertThatCode(() -> CertPathValidator.getInstance("PKIX").validate(path, params)).doesNotThrowAnyException();
	}

	@Test
	void refusesACallerWithNoClientCertificate() {
		KeyPair serverKey = MtlsTestSupport.generateEcKeyPair();
		ManagedChannel channel = MtlsTestSupport.channel(grpcPort(),
				MtlsTestSupport.clientSslContext(caCertificate(), null, null));
		try {
			StatusRuntimeException error = catchThrowableOfType(StatusRuntimeException.class,
					() -> GatewayIdentityGrpc.newBlockingStub(channel)
							.issueGatewayServerCertificate(request(MtlsTestSupport.csr(serverKey, "tls-server"))));
			assertThat(error.getStatus().getCode()).isEqualTo(Status.Code.UNAUTHENTICATED);
		} finally {
			shutdown(channel);
		}
	}

	@Test
	void refusesALockedGatewayIdentity() {
		String name = "gw-servercert-locked-" + unique();
		EnrolledGateway gateway = enroll(name);
		lockIdentity(gateway, "locked");

		StatusRuntimeException error = catchThrowableOfType(StatusRuntimeException.class,
				() -> issueServerCert(gateway, MtlsTestSupport.csr(MtlsTestSupport.generateEcKeyPair(), "tls-server")));
		assertThat(error.getStatus().getCode()).isEqualTo(Status.Code.PERMISSION_DENIED);
		assertThat(deniedIssuances(name)).isEqualTo(1L);
	}

	@Test
	void refusesARevokedGatewayIdentity() {
		String name = "gw-servercert-revoked-" + unique();
		EnrolledGateway gateway = enroll(name);
		lockIdentity(gateway, "revoked");

		StatusRuntimeException error = catchThrowableOfType(StatusRuntimeException.class,
				() -> issueServerCert(gateway, MtlsTestSupport.csr(MtlsTestSupport.generateEcKeyPair(), "tls-server")));

		assertThat(error.getStatus().getCode()).isEqualTo(Status.Code.PERMISSION_DENIED);
		assertThat(deniedIssuances(name)).isEqualTo(1L);
	}

	@Test
	void refusesAValidCertificateForAnUnknownGatewayIdentity() {
		KeyPair key = MtlsTestSupport.generateEcKeyPair();
		X509Certificate stranger = mintClientCert(key.getPublic(), UUID.randomUUID(), Instant.now().minusSeconds(60),
				Instant.now().plusSeconds(3600));

		StatusRuntimeException error = callWithClientCert(stranger, key);

		assertThat(error.getStatus().getCode()).isEqualTo(Status.Code.UNAUTHENTICATED);
	}

	@Test
	void refusesAnAgentPeerHoldingAValidAgentCertificate() {
		KeyPair key = MtlsTestSupport.generateEcKeyPair();
		X509Certificate agentLeaf = mintAgentClientCert(key.getPublic(), UUID.randomUUID());

		StatusRuntimeException error = callWithClientCert(agentLeaf, key);

		assertThat(error.getStatus().getCode()).isEqualTo(Status.Code.UNAUTHENTICATED);
	}

	@Test
	void refusesAnUnverifiableCsr() {
		EnrolledGateway gateway = enroll("gw-servercert-badcsr-" + unique());

		StatusRuntimeException error = catchThrowableOfType(StatusRuntimeException.class,
				() -> issueServerCert(gateway, new byte[]{1, 2, 3, 4}));

		assertThat(error.getStatus().getCode()).isEqualTo(Status.Code.INVALID_ARGUMENT);
	}

	private void lockIdentity(EnrolledGateway gateway, String status) {
		db.sql("UPDATE runtime.gateway_identity SET status = :status WHERE id = :id").bind("status", status)
				.bind("id", gateway.gatewayId()).fetch().rowsUpdated().block();
	}

	private Long deniedIssuances(String name) {
		return db
				.sql("SELECT count(*) FROM runtime.audit_event WHERE action = 'gateway.server_cert.issue' "
						+ "AND outcome = 'denied' AND actor = :actor")
				.bind("actor", name).map(row -> row.get(0, Long.class)).one().block();
	}

	private X509Certificate mintAgentClientCert(PublicKey publicKey, UUID agentId) {
		return mtlsCa.activeBackend().block()
				.issueLeaf(new LeafCertificateSpec(publicKey, "probe-agent", List.of("probe-agent"),
						List.of(AgentIdentityUri.of(agentId)), LeafPurpose.CLIENT,
						BigInteger.valueOf(System.nanoTime()), Instant.now().minusSeconds(60),
						Instant.now().plusSeconds(3600)));
	}

	private StatusRuntimeException callWithClientCert(X509Certificate leaf, KeyPair key) {
		SslContext ssl = MtlsTestSupport.clientSslContext(caCertificate(), leaf, key.getPrivate());
		ManagedChannel channel = MtlsTestSupport.channel(grpcPort(), ssl);
		try {
			byte[] csr = MtlsTestSupport.csr(MtlsTestSupport.generateEcKeyPair(), "tls-server");
			return catchThrowableOfType(StatusRuntimeException.class,
					() -> GatewayIdentityGrpc.newBlockingStub(channel).issueGatewayServerCertificate(request(csr)));
		} finally {
			shutdown(channel);
		}
	}

	private IssueGatewayServerCertificateResponse issueServerCert(EnrolledGateway gateway, byte[] csr) {
		SslContext ssl = MtlsTestSupport.clientSslContext(caCertificate(), gateway.certificate(),
				gateway.keyPair().getPrivate());
		ManagedChannel channel = MtlsTestSupport.channel(grpcPort(), ssl);
		try {
			return GatewayIdentityGrpc.newBlockingStub(channel).issueGatewayServerCertificate(request(csr));
		} finally {
			shutdown(channel);
		}
	}

	private static IssueGatewayServerCertificateRequest request(byte[] csr) {
		return IssueGatewayServerCertificateRequest.newBuilder().setPkcs10Csr(ByteString.copyFrom(csr)).build();
	}

	private static List<String> dnsSans(X509Certificate leaf) throws Exception {
		return sanValues(leaf.getSubjectAlternativeNames(), 2);
	}

	private static List<String> uriSans(X509Certificate leaf) throws Exception {
		return sanValues(leaf.getSubjectAlternativeNames(), 6);
	}

	private static List<String> sanValues(Collection<List<?>> sans, int generalNameType) {
		return sans.stream().filter(san -> ((Integer) san.get(0)) == generalNameType).map(san -> (String) san.get(1))
				.toList();
	}

	private static String unique() {
		return UUID.randomUUID().toString().substring(0, 8);
	}
}
