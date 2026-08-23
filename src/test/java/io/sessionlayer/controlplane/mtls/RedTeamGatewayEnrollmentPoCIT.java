package io.sessionlayer.controlplane.mtls;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.catchThrowable;

import com.google.protobuf.ByteString;
import io.grpc.ManagedChannel;
import io.grpc.StatusRuntimeException;
import io.netty.handler.ssl.SslContext;
import io.sessionlayer.controlplane.gateway.GatewayNames;
import io.sessionlayer.controlplane.grpc.v1.GatewayIdentityGrpc;
import io.sessionlayer.controlplane.grpc.v1.IssueGatewayServerCertificateRequest;
import io.sessionlayer.controlplane.grpc.v1.IssueGatewayServerCertificateResponse;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.Socket;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.Collection;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.Callable;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SNIHostName;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManagerFactory;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

/**
 * Impersonation proof of concept, kept as a regression test. A holder of
 * {@code gateway:enroll} could enroll a Gateway named after the Control Plane's
 * own hostname and then obtain a CA-signed serverAuth leaf whose CN and dNSName
 * SAN were that hostname, which any peer pinning the internal mTLS CA accepts
 * AS the Control Plane. The attack is spelled out step by step below and each
 * step now asserts that it is refused.
 */
class RedTeamGatewayEnrollmentPoCIT extends AbstractMtlsIT {

	private static final String SERVER_AUTH = "1.3.6.1.5.5.7.3.1";

	@Autowired
	private MtlsProperties mtlsProperties;

	@Test
	void cpHostnamesAreShapeValidButNotEnrollable() {
		List<String> cpHostnames = mtlsProperties.getServer().getHostnames();
		for (String hostname : cpHostnames) {
			// Shape validation still admits them -- they are ordinary DNS labels. The
			// reservation is a separate rule, so the two cannot be conflated by a future
			// caller reaching for isValid() when it means isEnrollable().
			assertThat(GatewayNames.isValid(hostname)).isTrue();
			assertThat(GatewayNames.isEnrollable(hostname, cpHostnames))
					.as("the CP's own hostname %s must not be enrollable as a Gateway", hostname).isFalse();
		}
		assertThat(GatewayNames.isEnrollable("controlplane", cpHostnames)).isFalse();
		assertThat(GatewayNames.isEnrollable("gw-1", cpHostnames)).isTrue();
		assertThat(GatewayNames.isEnrollable("sessionlayer-cp.svc.cluster.local", cpHostnames)).isTrue();
	}

	@Test
	void enrollingAsTheCpHostnameIsRefusedAtTheEnrollBoundary() throws Exception {
		String cpHostname = "controlplane";
		assertThat(mtlsProperties.getServer().getHostnames()).contains(cpHostname);

		// Mint straight through the service, bypassing the controller's check, to model
		// a token that predates the rule -- including one inserted into
		// runtime.gateway_enrollment_token by hand. Enroll is the boundary precisely
		// because mint-side validation cannot reach a row it never created.
		String token = enrollmentTokens.mint(cpHostname, "attacker-with-gateway-enroll", Duration.ofMinutes(10)).block()
				.rawToken();

		Throwable refused = catchThrowable(() -> enrollWithToken(cpHostname, token));
		assertThat(refused).as("enrolling under the CP's own hostname must be refused")
				.isInstanceOf(StatusRuntimeException.class);
		assertThat(refused).hasMessageContaining("INVALID_ARGUMENT");

		// The refusal has to be the NAME, not some incidental failure: the identical
		// flow with an ordinary name succeeds and yields a usable serverAuth leaf.
		String ordinary = "gw-ordinary-" + unique();
		EnrolledGateway benign = enroll(ordinary);
		KeyPair benignKey = MtlsTestSupport.generateEcKeyPair();
		X509Certificate benignLeaf = io.sessionlayer.controlplane.ca.mtls.X509Certificates.parse(
				issueServerCert(benign, MtlsTestSupport.csr(benignKey, "anything")).getCertificate().toByteArray());
		assertThat(benignLeaf.getExtendedKeyUsage()).contains(SERVER_AUTH);
		assertThat(dnsSans(benignLeaf)).containsExactly(ordinary);

		// And that leaf does not impersonate the CP either, which is what made the name
		// binding load-bearing in the first place. This mirrors the Gateway's real
		// admission test: chain to the pinned internal mTLS CA, then RFC 6125 name
		// match on the CP's server_name.
		Throwable control = tlsHandshake(benignLeaf, benignKey.getPrivate(), caCertificate(), cpHostname);
		assertThat(control).as("a leaf for an ordinary gateway name must not satisfy a client asking for the CP")
				.isNotNull();
	}

	@Test
	void reservationFoldsCaseAndTrailingDot() {
		// DNS name matching is ASCII-case-insensitive (RFC 4343) and a trailing root
		// dot
		// names the same host, so a reserved list compared literally is bypassed by
		// either. Both spellings produce a cert that satisfies a client asking for
		// "controlplane", so both must be refused.
		List<String> cpHostnames = mtlsProperties.getServer().getHostnames();
		for (String variant : List.of("CONTROLPLANE", "ControlPlane", "controlplane.", "CONTROLPLANE.")) {
			assertThat(GatewayNames.isEnrollable(variant, cpHostnames))
					.as("%s resolves to a reserved name and must not be enrollable", variant).isFalse();

			String token = enrollmentTokens.mint(variant, "attacker", Duration.ofMinutes(10)).block().rawToken();
			Throwable refused = catchThrowable(() -> enrollWithToken(variant, token));
			assertThat(refused).as("enrolling as %s must be refused", variant)
					.isInstanceOf(StatusRuntimeException.class);
		}
	}

	@Test
	void mintingForALiveGatewayNameCannotSupersedeIt() {
		String name = "gw-live-" + unique();
		EnrolledGateway live = enroll(name);

		String second = enrollmentTokens.mint(name, "attacker", Duration.ofMinutes(10)).block().rawToken();
		assertThat(second).isNotBlank();

		Throwable refused = catchThrowable(() -> enrollWithToken(name, second));
		System.out.println("[clean] re-enrolling a live name -> " + refused);
		assertThat(refused).isInstanceOf(StatusRuntimeException.class);
		Long identities = db.sql("SELECT count(*) FROM runtime.gateway_identity WHERE name = :n").bind("n", name)
				.map(row -> row.get(0, Long.class)).one().block();
		assertThat(identities).isEqualTo(1L);
		UUID stillTheSame = db.sql("SELECT id FROM runtime.gateway_identity WHERE name = :n").bind("n", name)
				.map(row -> row.get(0, UUID.class)).one().block();
		assertThat(stillTheSame).isEqualTo(live.gatewayId());
	}

	@Test
	void concurrentConsumeOfOneTokenAdmitsExactlyOneEnrollment() throws Exception {
		String name = "gw-race-" + unique();
		String token = enrollmentTokens.mint(name, "operator", Duration.ofMinutes(10)).block().rawToken();

		int threads = 8;
		CyclicBarrier gate = new CyclicBarrier(threads);
		ExecutorService pool = Executors.newFixedThreadPool(threads);
		try {
			List<Future<Boolean>> results = pool
					.invokeAll(java.util.Collections.nCopies(threads, (Callable<Boolean>) () -> {
						gate.await();
						try {
							enrollWithToken(name, token);
							return Boolean.TRUE;
						} catch (RuntimeException refused) {
							return Boolean.FALSE;
						}
					}));
			long won = results.stream().filter(f -> {
				try {
					return f.get();
				} catch (Exception e) {
					return false;
				}
			}).count();
			System.out.println("[clean] " + threads + "-way concurrent enroll on ONE token: winners=" + won);
			assertThat(won).isEqualTo(1L);
		} finally {
			pool.shutdownNow();
		}
		Long identities = db.sql("SELECT count(*) FROM runtime.gateway_identity WHERE name = :n").bind("n", name)
				.map(row -> row.get(0, Long.class)).one().block();
		assertThat(identities).isEqualTo(1L);
	}

	@Test
	void concurrentEnrollOfOneNameWithDistinctTokensYieldsOneIdentity() throws Exception {
		String name = "gw-namerace-" + unique();
		int threads = 6;
		List<String> tokens = new java.util.ArrayList<>();
		for (int i = 0; i < threads; i++) {
			tokens.add(enrollmentTokens.mint(name, "operator", Duration.ofMinutes(10)).block().rawToken());
		}
		CyclicBarrier gate = new CyclicBarrier(threads);
		ExecutorService pool = Executors.newFixedThreadPool(threads);
		try {
			List<Callable<Boolean>> jobs = new java.util.ArrayList<>();
			for (String token : tokens) {
				jobs.add(() -> {
					gate.await();
					try {
						enrollWithToken(name, token);
						return Boolean.TRUE;
					} catch (RuntimeException refused) {
						return Boolean.FALSE;
					}
				});
			}
			long won = pool.invokeAll(jobs).stream().filter(f -> {
				try {
					return f.get();
				} catch (Exception e) {
					return false;
				}
			}).count();
			System.out.println("[clean] " + threads + " DISTINCT tokens, same name, concurrent: winners=" + won);
			assertThat(won).isEqualTo(1L);
		} finally {
			pool.shutdownNow();
		}
		Long identities = db.sql("SELECT count(*) FROM runtime.gateway_identity WHERE name = :n").bind("n", name)
				.map(row -> row.get(0, Long.class)).one().block();
		System.out.println("[clean] gateway_identity rows for " + name + " = " + identities);
		assertThat(identities).isEqualTo(1L);
	}

	@Test
	void revokeBlocksAnUnusedTokenAndCannotTouchAnotherGateway() {
		String victim = "gw-victim-" + unique();
		String attackerName = "gw-attacker-" + unique();
		var victimToken = enrollmentTokens.mint(victim, "operator", Duration.ofMinutes(10)).block();
		var attackerToken = enrollmentTokens.mint(attackerName, "operator", Duration.ofMinutes(10)).block();

		enrollmentTokens.revoke(attackerToken.id()).block();
		assertThat(enrollmentTokens.isValid(victimToken.rawToken(), victim).block()).isTrue();
		assertThat(enrollmentTokens.isValid(attackerToken.rawToken(), attackerName).block()).isFalse();

		enrollmentTokens.revoke(attackerToken.id()).block();
		enrollmentTokens.revoke(UUID.randomUUID()).block();
		Throwable refused = catchThrowable(() -> enrollWithToken(attackerName, attackerToken.rawToken()));
		System.out.println("[clean] revoked token enroll -> " + refused);
		assertThat(refused).isInstanceOf(StatusRuntimeException.class);
	}

	@Test
	void gatewayNameValidatorRejectsTheUsualBypasses() {
		List<String> hostile = List.of("", " ", "gw 1", "gw/../etc", "gw\n", "gw\r\n", "gw\u0000", "gw\u0000x",
				"CN=x,OU=y", "gw,O=evil", "*.example.com", "gw\u00ad1", "gw\u3002x", "gwｰ1", "gw%2e%2e", "a".repeat(65),
				"gw:1", "gw@1", "gw#1", "gw\t1", "gw+1", "sessionlayer://gateway/x");
		for (String candidate : hostile) {
			boolean valid = GatewayNames.isValid(candidate);
			System.out.println("[clean] isValid("
					+ candidate.replace("\n", "\\n").replace("\r", "\\r").replace("\u0000", "\\0").replace("\t", "\\t")
					+ ") = " + valid);
			assertThat(valid).as("hostile name %s must be rejected", candidate).isFalse();
		}
		assertThat(GatewayNames.isValid(null)).isFalse();
		assertThat(GatewayNames.isValid("a".repeat(64))).isTrue();
		// Trailing dot and leading dash ARE accepted (name-shape laxness, not a bypass
		// of the DB uniqueness that guards live gateways).
		System.out.println("[clean] isValid(\"gw1.\") = " + GatewayNames.isValid("gw1."));
		System.out.println("[clean] isValid(\"-gw1\") = " + GatewayNames.isValid("-gw1"));
		System.out.println("[clean] isValid(\"..\")   = " + GatewayNames.isValid(".."));
	}

	@Test
	void expiredTokenIsRefusedAtTheBoundary() {
		String name = "gw-exp-" + unique();
		var minted = enrollmentTokens.mint(name, "operator", Duration.ofSeconds(1)).block();
		db.sql("UPDATE runtime.gateway_enrollment_token SET expires_at = now() - interval '1 second' WHERE id = :id")
				.bind("id", minted.id()).fetch().rowsUpdated().block();
		assertThat(enrollmentTokens.isValid(minted.rawToken(), name).block()).isFalse();
		Throwable refused = catchThrowable(() -> enrollWithToken(name, minted.rawToken()));
		System.out.println("[clean] expired token enroll -> " + refused);
		assertThat(refused).isInstanceOf(StatusRuntimeException.class);
	}

	@Test
	void neitherTheRawTokenNorItsHashEverReachesTheAuditStream() {
		String name = "gw-audit-" + unique();
		var minted = enrollmentTokens.mint(name, "operator", Duration.ofMinutes(10)).block();
		enrollWithToken(name, minted.rawToken());
		String hash = io.sessionlayer.controlplane.gateway.SingleUseTokens.hash(minted.rawToken());

		for (String needle : List.of(minted.rawToken(), hash)) {
			Long hits = db
					.sql("SELECT count(*) FROM runtime.audit_event WHERE detail::text LIKE :needle "
							+ "OR subject LIKE :needle OR actor LIKE :needle")
					.bind("needle", "%" + needle + "%").map(row -> row.get(0, Long.class)).one().block();
			System.out.println("[clean] audit rows containing " + needle.substring(0, 8) + "... = " + hits);
			assertThat(hits).isEqualTo(0L);
		}
	}

	private static Throwable tlsHandshake(X509Certificate leaf, PrivateKey key, X509Certificate pinnedCa,
			String expectedName) throws Exception {
		KeyStore serverStore = KeyStore.getInstance("PKCS12");
		serverStore.load(null, null);
		serverStore.setKeyEntry("leaf", key, "x".toCharArray(), new Certificate[]{leaf});
		KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
		kmf.init(serverStore, "x".toCharArray());
		SSLContext serverCtx = SSLContext.getInstance("TLSv1.3");
		serverCtx.init(kmf.getKeyManagers(), null, null);

		KeyStore trustStore = KeyStore.getInstance("PKCS12");
		trustStore.load(null, null);
		trustStore.setCertificateEntry("pinned-ca", pinnedCa);
		TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
		tmf.init(trustStore);
		SSLContext clientCtx = SSLContext.getInstance("TLSv1.3");
		clientCtx.init(null, tmf.getTrustManagers(), null);

		try (SSLServerSocket server = (SSLServerSocket) serverCtx.getServerSocketFactory().createServerSocket(0, 1,
				InetAddress.getLoopbackAddress())) {
			server.setEnabledProtocols(new String[]{"TLSv1.3"});
			int port = server.getLocalPort();
			Thread accept = new Thread(() -> {
				try (SSLSocket peer = (SSLSocket) server.accept()) {
					peer.setSoTimeout(5000);
					OutputStream out = peer.getOutputStream();
					out.write('o');
					out.flush();
				} catch (Exception ignored) {
					// the client-side outcome is what this probe measures
				}
			});
			accept.setDaemon(true);
			accept.start();

			try (Socket plain = new Socket(InetAddress.getLoopbackAddress(), port)) {
				// createSocket(Socket, host, port, autoClose) takes `host` as the peer identity
				// for endpoint identification WITHOUT re-resolving it - exactly the
				// "connect to this address, verify this name" shape the Gateway uses.
				SSLSocket client = (SSLSocket) clientCtx.getSocketFactory().createSocket(plain, expectedName, port,
						true);
				SSLParameters params = client.getSSLParameters();
				params.setEndpointIdentificationAlgorithm("HTTPS");
				params.setServerNames(List.of(new SNIHostName(expectedName)));
				client.setSSLParameters(params);
				client.setSoTimeout(5000);
				client.startHandshake();
				InputStream in = client.getInputStream();
				in.read();
				return null;
			} catch (Exception rejected) {
				return rejected;
			} finally {
				accept.join(2000);
			}
		}
	}

	private IssueGatewayServerCertificateResponse issueServerCert(EnrolledGateway gateway, byte[] csr) {
		SslContext ssl = MtlsTestSupport.clientSslContext(caCertificate(), gateway.certificate(),
				gateway.keyPair().getPrivate());
		ManagedChannel channel = MtlsTestSupport.channel(grpcPort(), ssl);
		try {
			return GatewayIdentityGrpc.newBlockingStub(channel).issueGatewayServerCertificate(
					IssueGatewayServerCertificateRequest.newBuilder().setPkcs10Csr(ByteString.copyFrom(csr)).build());
		} finally {
			shutdown(channel);
		}
	}

	private static List<String> dnsSans(X509Certificate leaf) throws Exception {
		Collection<List<?>> sans = leaf.getSubjectAlternativeNames();
		return sans == null
				? List.of()
				: sans.stream().filter(san -> ((Integer) san.get(0)) == 2).map(san -> (String) san.get(1)).toList();
	}

	private static String unique() {
		return UUID.randomUUID().toString().substring(0, 8);
	}
}
