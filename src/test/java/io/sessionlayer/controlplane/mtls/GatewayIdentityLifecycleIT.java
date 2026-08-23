package io.sessionlayer.controlplane.mtls;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.catchThrowableOfType;

import com.google.protobuf.ByteString;
import io.grpc.ManagedChannel;
import io.grpc.Status;
import io.grpc.StatusRuntimeException;
import io.netty.handler.ssl.SslContext;
import io.sessionlayer.controlplane.data.runtime.GatewayIdentity;
import io.sessionlayer.controlplane.grpc.v1.GatewayIdentityGrpc;
import io.sessionlayer.controlplane.grpc.v1.RenewGatewayIdentityRequest;
import io.sessionlayer.controlplane.grpc.v1.RenewGatewayIdentityResponse;
import java.security.KeyPair;
import org.junit.jupiter.api.Test;

class GatewayIdentityLifecycleIT extends AbstractMtlsIT {

	@Test
	void enrollIssuesGenerationZeroAndWritesIdentity() {
		EnrolledGateway gateway = enroll("gw-enroll");
		assertThat(gateway.generation()).isZero();

		GatewayIdentity identity = gatewayIdentities.findById(gateway.gatewayId()).block();
		assertThat(identity).isNotNull();
		assertThat(identity.name()).isEqualTo("gw-enroll");
		assertThat(identity.generation()).isZero();
		assertThat(identity.status()).isEqualTo("active");
		assertThat(identity.joinMethod()).isEqualTo("token");
		assertThat(identity.mtlsIdentityRef()).isEqualTo("mtls:" + gateway.gatewayId());
		assertThat(identity.fingerprint()).isNotBlank();
	}

	@Test
	void enrollmentTokenIsSingleUse() {
		String token = enrollmentTokens.mint("gw-single-use", "test-operator").block();
		EnrolledGateway first = enrollWithToken("gw-single-use", token);
		assertThat(first.generation()).isZero();

		StatusRuntimeException replay = catchThrowableOfType(StatusRuntimeException.class,
				() -> enrollWithToken("gw-single-use-2", token));
		assertThat(replay.getStatus().getCode()).isEqualTo(Status.Code.UNAUTHENTICATED);
	}

	@Test
	void enrollErrorIsIndistinguishableForAlreadyEnrolledAndInvalidToken() {
		// Responses for already-enrolled and invalid-token must be indistinguishable
		// to prevent gateway enumeration.
		enroll("gw-oracle");
		String freshToken = enrollmentTokens.mint("gw-oracle", "test-operator").block();
		StatusRuntimeException alreadyEnrolled = catchThrowableOfType(StatusRuntimeException.class,
				() -> enrollWithToken("gw-oracle", freshToken));
		StatusRuntimeException invalidToken = catchThrowableOfType(StatusRuntimeException.class,
				() -> enrollWithToken("gw-oracle-free", "not-a-real-token"));
		assertThat(alreadyEnrolled.getStatus().getCode()).isEqualTo(Status.Code.UNAUTHENTICATED);
		assertThat(invalidToken.getStatus().getCode()).isEqualTo(Status.Code.UNAUTHENTICATED);
		assertThat(alreadyEnrolled.getStatus().getDescription()).isEqualTo(invalidToken.getStatus().getDescription());
		Long unconsumed = db.sql(
				"SELECT count(*) FROM runtime.gateway_enrollment_token WHERE gateway_name = 'gw-oracle' AND consumed_at IS NULL")
				.map(row -> row.get(0, Long.class)).one().block();
		assertThat(unconsumed).isEqualTo(1L);
	}

	@Test
	void renewRotatesCertificateAndIncrementsGeneration() {
		EnrolledGateway gateway = enroll("gw-renew");
		String beforeFingerprint = gatewayIdentities.findById(gateway.gatewayId()).block().fingerprint();

		RenewGatewayIdentityResponse renewed = renew(gateway, "gw-renew", 0);
		assertThat(renewed.getGeneration()).isEqualTo(1);

		GatewayIdentity after = gatewayIdentities.findById(gateway.gatewayId()).block();
		assertThat(after.generation()).isEqualTo(1);
		assertThat(after.fingerprint()).isNotEqualTo(beforeFingerprint);
	}

	@Test
	void lockedIdentityIsRefusedForRenew() {
		EnrolledGateway gateway = enroll("gw-locked");
		db.sql("UPDATE runtime.gateway_identity SET status = 'locked' WHERE id = :id").bind("id", gateway.gatewayId())
				.fetch().rowsUpdated().block();

		StatusRuntimeException error = catchThrowableOfType(StatusRuntimeException.class,
				() -> renew(gateway, "gw-locked", 0));
		assertThat(error.getStatus().getCode()).isEqualTo(Status.Code.PERMISSION_DENIED);
	}

	@Test
	void generationMismatchIsRefusedAndFlagged() {
		EnrolledGateway gateway = enroll("gw-genmismatch");

		StatusRuntimeException error = catchThrowableOfType(StatusRuntimeException.class,
				() -> renew(gateway, "gw-genmismatch", 5));
		assertThat(error.getStatus().getCode()).isEqualTo(Status.Code.FAILED_PRECONDITION);
		Long flagged = db
				.sql("SELECT count(*) FROM runtime.audit_event WHERE action = 'gateway.renew.generation_mismatch' "
						+ "AND actor = 'gw-genmismatch'")
				.map(row -> row.get(0, Long.class)).one().block();
		assertThat(flagged).isGreaterThanOrEqualTo(1L);
	}

	private RenewGatewayIdentityResponse renew(EnrolledGateway gateway, String name, long currentGeneration) {
		KeyPair newKey = MtlsTestSupport.generateEcKeyPair();
		SslContext ssl = MtlsTestSupport.clientSslContext(caCertificate(), gateway.certificate(),
				gateway.keyPair().getPrivate());
		ManagedChannel channel = MtlsTestSupport.channel(grpcPort(), ssl);
		try {
			return GatewayIdentityGrpc.newBlockingStub(channel)
					.renewGatewayIdentity(RenewGatewayIdentityRequest.newBuilder()
							.setPkcs10Csr(ByteString.copyFrom(MtlsTestSupport.csr(newKey, name)))
							.setCurrentGeneration(currentGeneration).build());
		} finally {
			shutdown(channel);
		}
	}
}
