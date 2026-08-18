package io.sessionlayer.controlplane.mtls;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.catchThrowableOfType;

import io.grpc.Status;
import io.grpc.StatusRuntimeException;
import io.sessionlayer.controlplane.ca.CaSignerService;
import io.sessionlayer.controlplane.ca.wire.SshReader;
import io.sessionlayer.controlplane.data.runtime.SessionSigningToken;
import io.sessionlayer.controlplane.data.runtime.SessionSigningTokenRepository;
import io.sessionlayer.controlplane.gateway.SingleUseTokens;
import io.sessionlayer.controlplane.grpc.v1.SignContext;
import io.sessionlayer.controlplane.grpc.v1.SignSessionCertificateRequest;
import io.sessionlayer.controlplane.grpc.v1.SignSessionCertificateResponse;
import java.security.KeyPair;
import java.security.interfaces.ECPublicKey;
import java.time.Instant;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

class SessionSigningIT extends AbstractMtlsIT {

	@Autowired
	private SessionSigningTokenRepository signingTokenRepository;
	@Autowired
	private CaSignerService caSigner;

	@Test
	void validRequestReturnsCertificateOnly() {
		EnrolledGateway gateway = enroll("gw-sign");
		UUID sessionId = UUID.randomUUID();
		UUID nodeId = UUID.randomUUID();
		String token = signingTokens
				.mint(gateway.gatewayId(), sessionId, nodeId, "deploy", List.of("shell", "exec"), "10.0.0.0/8").block();

		KeyPair inner = MtlsTestSupport.generateEcKeyPair();
		SignSessionCertificateResponse response = sign(gateway, token,
				MtlsTestSupport.opensshPublicKeyBlob((ECPublicKey) inner.getPublic()), null);

		assertThat(response.getCertificateLine()).startsWith("ecdsa-sha2-nistp256-cert-v01@openssh.com");
		assertThat(response.getKeyId()).isEqualTo(sessionId + "+deploy");
		assertThat(response.getCertificateLine()).doesNotContain("PRIVATE KEY");
		byte[] caBlob = caSigner.activeSigner("session").block().caPublicKeyBlob();
		assertThat(signatureKeyOf(response.getCertificateBlob().toByteArray())).isEqualTo(caBlob);
		assertThat(principalsOf(response.getCertificateBlob().toByteArray())).containsExactly("deploy");
	}

	// Even when the session token carries a source-address, the node-facing inner
	// cert MUST omit it - the node validates source-address against the Gateway's
	// peer IP, not the client's, so a client-IP pin breaks any multi-host / NAT
	// deployment.
	@Test
	void mintedInnerCertOmitsSourceAddress() {
		EnrolledGateway gateway = enroll("gw-nosrcaddr");
		String token = signingTokens.mint(gateway.gatewayId(), UUID.randomUUID(), UUID.randomUUID(), "deploy",
				List.of("shell"), "10.0.0.0/8").block();

		KeyPair inner = MtlsTestSupport.generateEcKeyPair();
		SignSessionCertificateResponse response = sign(gateway, token,
				MtlsTestSupport.opensshPublicKeyBlob((ECPublicKey) inner.getPublic()), null);
		assertThat(criticalOptionsOf(response.getCertificateBlob().toByteArray())).isEmpty();
	}

	@Test
	void crossGatewayTokenIsRejected() {
		EnrolledGateway owner = enroll("gw-owner");
		EnrolledGateway attacker = enroll("gw-attacker");
		String token = signingTokens
				.mint(owner.gatewayId(), UUID.randomUUID(), UUID.randomUUID(), "deploy", List.of("shell"), null)
				.block();

		KeyPair inner = MtlsTestSupport.generateEcKeyPair();
		StatusRuntimeException error = catchThrowableOfType(StatusRuntimeException.class, () -> sign(attacker, token,
				MtlsTestSupport.opensshPublicKeyBlob((ECPublicKey) inner.getPublic()), null));
		assertThat(error.getStatus().getCode()).isEqualTo(Status.Code.PERMISSION_DENIED);
	}

	@Test
	void crossSessionContextIsRejected() {
		EnrolledGateway gateway = enroll("gw-crosssession");
		UUID sessionId = UUID.randomUUID();
		String token = signingTokens
				.mint(gateway.gatewayId(), sessionId, UUID.randomUUID(), "deploy", List.of("shell"), null).block();

		KeyPair inner = MtlsTestSupport.generateEcKeyPair();
		SignContext mismatched = SignContext.newBuilder().setSessionId(UUID.randomUUID().toString()).build();
		StatusRuntimeException error = catchThrowableOfType(StatusRuntimeException.class, () -> sign(gateway, token,
				MtlsTestSupport.opensshPublicKeyBlob((ECPublicKey) inner.getPublic()), mismatched));
		assertThat(error.getStatus().getCode()).isEqualTo(Status.Code.PERMISSION_DENIED);
	}

	@Test
	void expiredTokenIsRejected() {
		EnrolledGateway gateway = enroll("gw-expiredtoken");
		SingleUseTokens.Minted minted = SingleUseTokens.mint();
		signingTokenRepository.save(SessionSigningToken.create(minted.hash(), gateway.gatewayId(), UUID.randomUUID(),
				UUID.randomUUID(), "deploy", List.of("shell"), null, Instant.now().minusSeconds(60))).block();

		KeyPair inner = MtlsTestSupport.generateEcKeyPair();
		StatusRuntimeException error = catchThrowableOfType(StatusRuntimeException.class, () -> sign(gateway,
				minted.raw(), MtlsTestSupport.opensshPublicKeyBlob((ECPublicKey) inner.getPublic()), null));
		assertThat(error.getStatus().getCode()).isEqualTo(Status.Code.PERMISSION_DENIED);
	}

	@Test
	void replayedTokenIsRejected() {
		EnrolledGateway gateway = enroll("gw-replay");
		String token = signingTokens
				.mint(gateway.gatewayId(), UUID.randomUUID(), UUID.randomUUID(), "deploy", List.of("shell"), null)
				.block();

		KeyPair inner = MtlsTestSupport.generateEcKeyPair();
		byte[] pub = MtlsTestSupport.opensshPublicKeyBlob((ECPublicKey) inner.getPublic());
		assertThat(sign(gateway, token, pub, null).getCertificateLine()).isNotBlank();

		StatusRuntimeException replay = catchThrowableOfType(StatusRuntimeException.class,
				() -> sign(gateway, token, pub, null));
		assertThat(replay.getStatus().getCode()).isEqualTo(Status.Code.PERMISSION_DENIED);
	}

	@Test
	void requestCarriesOnlyAPublicKeyNoPrivateMaterial() {
		Set<String> fields = SignSessionCertificateRequest.getDescriptor().getFields().stream().map(f -> f.getName())
				.collect(java.util.stream.Collectors.toSet());
		assertThat(fields).containsExactlyInAnyOrder("session_token", "subject_public_key", "context");
		assertThat(fields).noneMatch(name -> name.toLowerCase(java.util.Locale.ROOT).contains("private"));
	}

	private SignSessionCertificateResponse sign(EnrolledGateway gateway, String rawToken, byte[] subjectPublicKeyBlob,
			SignContext context) {
		return signSessionCertificate(gateway, rawToken, subjectPublicKeyBlob, context);
	}

	private static byte[] signatureKeyOf(byte[] certBlob) {
		SshReader reader = new SshReader(certBlob);
		reader.readString();
		reader.readString();
		reader.readString();
		reader.readString();
		reader.readUint64();
		reader.readUint32();
		reader.readString();
		reader.readString();
		reader.readUint64();
		reader.readUint64();
		reader.readString();
		reader.readString();
		reader.readString();
		return reader.readString();
	}

	private static byte[] criticalOptionsOf(byte[] certBlob) {
		SshReader reader = new SshReader(certBlob);
		for (int i = 0; i < 4; i++) {
			reader.readString();
		}
		reader.readUint64();
		reader.readUint32();
		reader.readString();
		reader.readString();
		reader.readUint64();
		reader.readUint64();
		return reader.readString();
	}

	private static List<String> principalsOf(byte[] certBlob) {
		SshReader reader = new SshReader(certBlob);
		for (int i = 0; i < 4; i++) {
			reader.readString();
		}
		reader.readUint64();
		reader.readUint32();
		reader.readString();
		byte[] principalsField = reader.readString();
		SshReader principals = new SshReader(principalsField);
		java.util.List<String> out = new java.util.ArrayList<>();
		while (principals.hasRemaining()) {
			out.add(principals.readStringUtf8());
		}
		return out;
	}
}
