package io.sessionlayer.controlplane.grpc;

import io.grpc.Status;
import io.grpc.StatusRuntimeException;
import io.sessionlayer.controlplane.agent.AgentJoinException;
import io.sessionlayer.controlplane.ca.CaSignerService;
import io.sessionlayer.controlplane.ca.backend.CaSigningFailedException;
import io.sessionlayer.controlplane.ca.mtls.InternalMtlsCaService;
import io.sessionlayer.controlplane.device.DeviceFlowService;
import io.sessionlayer.controlplane.gateway.GatewayRequestException;
import java.util.concurrent.TimeoutException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Maps service exceptions to fail-closed gRPC statuses with <b>generic,
 * non-leaking</b> descriptions. The specific cause is logged server-side and
 * never returned to the caller, so a client cannot distinguish (say) "expired
 * token" from "wrong gateway". A CA/signer that is unavailable is a transient
 * server condition ({@code UNAVAILABLE}); anything unexpected is a generic
 * {@code INTERNAL}.
 */
final class GrpcErrors {

	private static final Logger LOG = LoggerFactory.getLogger(GrpcErrors.class);

	private GrpcErrors() {
	}

	static StatusRuntimeException toStatus(Throwable error, String operation) {
		if (error instanceof GatewayRequestException request) {
			Status status = switch (request.reason()) {
				case UNAUTHENTICATED -> Status.UNAUTHENTICATED;
				case PERMISSION_DENIED -> Status.PERMISSION_DENIED;
				case FAILED_PRECONDITION -> Status.FAILED_PRECONDITION;
				case INVALID_ARGUMENT -> Status.INVALID_ARGUMENT;
			};
			return status.withDescription(request.getMessage()).asRuntimeException();
		}
		if (error instanceof AgentJoinException request) {
			Status status = switch (request.reason()) {
				case UNAUTHENTICATED -> Status.UNAUTHENTICATED;
				case PERMISSION_DENIED -> Status.PERMISSION_DENIED;
				case FAILED_PRECONDITION -> Status.FAILED_PRECONDITION;
				case INVALID_ARGUMENT -> Status.INVALID_ARGUMENT;
			};
			return status.withDescription(request.getMessage()).asRuntimeException();
		}
		if (error instanceof DeviceFlowService.RateLimited) {
			return Status.RESOURCE_EXHAUSTED.withDescription("rate limited").asRuntimeException();
		}
		if (error instanceof InternalMtlsCaService.NoMtlsCaAvailable
				|| error instanceof CaSignerService.NoSignerAvailable) {
			LOG.warn("gRPC {} refused — CA unavailable: {}", operation, error.getMessage());
			return Status.UNAVAILABLE.withDescription("certificate authority unavailable").asRuntimeException();
		}
		if (error instanceof CaSigningFailedException) {
			// The CA was reached and refused. Deliberately not UNAVAILABLE and not
			// INTERNAL: the first tells a Gateway to retry elsewhere, the second reads
			// as an outage, and a vault returning a signature that fails verification is
			// neither. The description carries no key-service response content.
			LOG.warn("gRPC {} refused — CA signing failed: {}", operation, error.getMessage());
			return Status.FAILED_PRECONDITION.withDescription("certificate authority refused to sign")
					.asRuntimeException();
		}
		if (error instanceof TimeoutException) {
			LOG.warn("gRPC {} exceeded the server deadline", operation);
			return Status.DEADLINE_EXCEEDED.withDescription("request deadline exceeded").asRuntimeException();
		}
		LOG.warn("gRPC {} failed", operation, error);
		return Status.INTERNAL.withDescription("internal error").asRuntimeException();
	}
}
