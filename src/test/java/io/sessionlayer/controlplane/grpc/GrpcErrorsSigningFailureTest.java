package io.sessionlayer.controlplane.grpc;

import static org.assertj.core.api.Assertions.assertThat;

import io.grpc.Status;
import io.grpc.StatusRuntimeException;
import io.sessionlayer.controlplane.ca.CaSignerService;
import io.sessionlayer.controlplane.ca.backend.azure.AzureKeyVaultSigner;
import org.junit.jupiter.api.Test;

/**
 * A CA that was reached and refused must be distinguishable, on the wire, from
 * a CA that could not be reached — and neither may carry what the key service
 * said.
 */
class GrpcErrorsSigningFailureTest {

	private static final String VAULT_RESPONSE = "SECRET-VAULT-RESPONSE-BODY";

	private static StatusRuntimeException signingFailure() {
		Throwable cause = new IllegalStateException("Status code 403, \"" + VAULT_RESPONSE + "\"");
		AzureKeyVaultSigner signer = new AzureKeyVaultSigner(null, null, "https://v.example.net/keys/k/0");
		try {
			signer.signDigestP1363(new byte[1]); // wrong digest length -> the seam's own failure
			throw new AssertionError("expected the signer to reject a short digest");
		} catch (RuntimeException expected) {
			return GrpcErrors.toStatus(expected.initCause(cause) == null ? expected : expected,
					"SignSessionCertificate");
		}
	}

	/**
	 * {@code UNAVAILABLE} tells a Gateway the Control Plane is down and to treat
	 * this as an outage; {@code INTERNAL} reads as a bug. A vault returning a
	 * signature that fails verification is neither, and reporting it as either
	 * sends an operator to look in the wrong place.
	 */
	@Test
	void aBackendThatRefusedIsNotReportedAsAnOutage() {
		StatusRuntimeException status = signingFailure();

		assertThat(status.getStatus().getCode()).isEqualTo(Status.Code.FAILED_PRECONDITION);
		assertThat(status.getStatus().getCode()).isNotEqualTo(Status.Code.UNAVAILABLE);
		assertThat(status.getStatus().getCode()).isNotEqualTo(Status.Code.INTERNAL);
	}

	/** An absent CA keeps its own, different status — the two must not collapse. */
	@Test
	void anAbsentCaStillReportsUnavailable() {
		StatusRuntimeException status = GrpcErrors
				.toStatus(new CaSignerService.NoSignerAvailable("no active session CA"), "SignSessionCertificate");

		assertThat(status.getStatus().getCode()).isEqualTo(Status.Code.UNAVAILABLE);
	}

	/**
	 * The cause is deliberately retained for an operator reading a stack trace, so
	 * the guard that matters is that nothing it carries reaches the wire.
	 */
	@Test
	void theWireDescriptionCarriesNoKeyServiceResponse() {
		StatusRuntimeException status = signingFailure();

		assertThat(status.getStatus().getDescription()).doesNotContain(VAULT_RESPONSE).doesNotContain("403");
	}
}
