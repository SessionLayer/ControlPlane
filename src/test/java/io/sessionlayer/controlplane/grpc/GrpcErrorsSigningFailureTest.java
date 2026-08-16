package io.sessionlayer.controlplane.grpc;

import static org.assertj.core.api.Assertions.assertThat;

import io.grpc.Status;
import io.grpc.StatusRuntimeException;
import io.sessionlayer.controlplane.ca.CaSignerService;
import io.sessionlayer.controlplane.ca.backend.azure.AzureKeyVaultSigner;
import org.junit.jupiter.api.Test;

class GrpcErrorsSigningFailureTest {

	private static final String VAULT_RESPONSE = "SECRET-VAULT-RESPONSE-BODY";

	private static StatusRuntimeException signingFailure() {
		Throwable cause = new IllegalStateException("Status code 403, \"" + VAULT_RESPONSE + "\"");
		AzureKeyVaultSigner signer = new AzureKeyVaultSigner(null, null, "https://v.example.net/keys/k/0");
		try {
			signer.signDigestP1363(new byte[1]);
			throw new AssertionError("expected the signer to reject a short digest");
		} catch (RuntimeException expected) {
			return GrpcErrors.toStatus(expected.initCause(cause) == null ? expected : expected,
					"SignSessionCertificate");
		}
	}

	@Test
	void aBackendThatRefusedIsNotReportedAsAnOutage() {
		StatusRuntimeException status = signingFailure();

		assertThat(status.getStatus().getCode()).isEqualTo(Status.Code.FAILED_PRECONDITION);
		assertThat(status.getStatus().getCode()).isNotEqualTo(Status.Code.UNAVAILABLE);
		assertThat(status.getStatus().getCode()).isNotEqualTo(Status.Code.INTERNAL);
	}

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
