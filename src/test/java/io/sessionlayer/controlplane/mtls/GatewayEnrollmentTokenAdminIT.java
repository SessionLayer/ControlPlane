package io.sessionlayer.controlplane.mtls;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.catchThrowableOfType;

import io.grpc.Status;
import io.grpc.StatusRuntimeException;
import io.sessionlayer.controlplane.data.runtime.GatewayEnrollmentToken;
import io.sessionlayer.controlplane.gateway.GatewayEnrollmentTokenService.MintedEnrollmentToken;
import java.time.Duration;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;

/**
 * The admin-issued token must authorise exactly the enrollment the gRPC path
 * already performs - once, for that name, before it expires - and revocation
 * must close it without deleting the row (V15: cp_runtime holds no DELETE).
 */
class GatewayEnrollmentTokenAdminIT extends AbstractMtlsIT {

	@Test
	void anAdminIssuedTokenEnrollsOnceThenIsRefused() {
		MintedEnrollmentToken minted = enrollmentTokens.mint("gw-admin-once", "operator", Duration.ofMinutes(10))
				.block();

		EnrolledGateway enrolled = enrollWithToken("gw-admin-once", minted.rawToken());
		assertThat(enrolled.generation()).isZero();

		StatusRuntimeException replay = catchThrowableOfType(StatusRuntimeException.class,
				() -> enrollWithToken("gw-admin-once-2", minted.rawToken()));
		assertThat(replay.getStatus().getCode()).isEqualTo(Status.Code.UNAUTHENTICATED);
	}

	@Test
	void aTokenIsBoundToTheNameItWasIssuedFor() {
		MintedEnrollmentToken minted = enrollmentTokens.mint("gw-admin-bound", "operator", Duration.ofMinutes(10))
				.block();

		StatusRuntimeException wrongName = catchThrowableOfType(StatusRuntimeException.class,
				() -> enrollWithToken("gw-admin-other", minted.rawToken()));
		assertThat(wrongName.getStatus().getCode()).isEqualTo(Status.Code.UNAUTHENTICATED);
	}

	/**
	 * Defence in depth: a token minted straight into the table (as the install
	 * guide used to instruct) bypasses the mint-time check, so enrollment must
	 * refuse the CP's own hostname on its own.
	 */
	@Test
	void enrollingAsTheControlPlanesOwnHostnameIsRefusedEvenWithAValidToken() {
		String cpHostname = "controlplane";
		MintedEnrollmentToken minted = enrollmentTokens.mint(cpHostname, "operator", Duration.ofMinutes(10)).block();

		StatusRuntimeException refused = catchThrowableOfType(StatusRuntimeException.class,
				() -> enrollWithToken(cpHostname, minted.rawToken()));
		assertThat(refused.getStatus().getCode()).isEqualTo(Status.Code.INVALID_ARGUMENT);

		assertThat(gatewayIdentities.findByName(cpHostname).blockOptional()).isEmpty();
	}

	@Test
	void anExpiredTokenIsRefused() {
		MintedEnrollmentToken expired = enrollmentTokens.mint("gw-admin-expired", "operator", Duration.ofSeconds(-1))
				.block();
		assertThat(enrollmentTokens.isValid(expired.rawToken(), "gw-admin-expired").block()).isFalse();

		StatusRuntimeException refused = catchThrowableOfType(StatusRuntimeException.class,
				() -> enrollWithToken("gw-admin-expired", expired.rawToken()));
		assertThat(refused.getStatus().getCode()).isEqualTo(Status.Code.UNAUTHENTICATED);
	}

	@Test
	void aRevokedTokenCannotEnroll() {
		MintedEnrollmentToken minted = enrollmentTokens.mint("gw-admin-revoked", "operator", Duration.ofMinutes(10))
				.block();
		assertThat(enrollmentTokens.isValid(minted.rawToken(), "gw-admin-revoked").block()).isTrue();

		enrollmentTokens.revoke(minted.id()).block();

		assertThat(enrollmentTokens.isValid(minted.rawToken(), "gw-admin-revoked").block()).isFalse();
		StatusRuntimeException refused = catchThrowableOfType(StatusRuntimeException.class,
				() -> enrollWithToken("gw-admin-revoked", minted.rawToken()));
		assertThat(refused.getStatus().getCode()).isEqualTo(Status.Code.UNAUTHENTICATED);
	}

	@Test
	void revokeMarksConsumedWithoutDeletingAndIsIdempotent() {
		MintedEnrollmentToken minted = enrollmentTokens.mint("gw-admin-idem", "operator", Duration.ofMinutes(10))
				.block();

		enrollmentTokens.revoke(minted.id()).block();
		enrollmentTokens.revoke(minted.id()).block();
		enrollmentTokens.revoke(UUID.randomUUID()).block();

		Long rows = db.sql("SELECT count(*) AS c FROM runtime.gateway_enrollment_token WHERE id = :id")
				.bind("id", minted.id()).map(row -> row.get("c", Long.class)).one().block();
		assertThat(rows).isEqualTo(1L);

		Long consumed = db
				.sql("SELECT count(*) AS c FROM runtime.gateway_enrollment_token "
						+ "WHERE id = :id AND consumed_at IS NOT NULL")
				.bind("id", minted.id()).map(row -> row.get("c", Long.class)).one().block();
		assertThat(consumed).isEqualTo(1L);
	}

	@Test
	void listActiveExcludesConsumedAndExpired() {
		MintedEnrollmentToken live = enrollmentTokens.mint("gw-admin-live", "operator", Duration.ofMinutes(10)).block();
		MintedEnrollmentToken revoked = enrollmentTokens.mint("gw-admin-gone", "operator", Duration.ofMinutes(10))
				.block();
		MintedEnrollmentToken expired = enrollmentTokens.mint("gw-admin-stale", "operator", Duration.ofSeconds(-1))
				.block();
		enrollmentTokens.revoke(revoked.id()).block();

		List<UUID> active = enrollmentTokens.listActive().map(GatewayEnrollmentToken::id).collectList().block();
		assertThat(active).contains(live.id()).doesNotContain(revoked.id()).doesNotContain(expired.id());
	}
}
