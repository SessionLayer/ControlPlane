package io.sessionlayer.controlplane.grpc;

import com.google.protobuf.ByteString;
import io.grpc.stub.StreamObserver;
import io.sessionlayer.controlplane.gateway.GatewayRequestException;
import io.sessionlayer.controlplane.gateway.SessionCertificateService;
import io.sessionlayer.controlplane.gateway.SignRequestContext;
import io.sessionlayer.controlplane.gateway.SignedInnerCert;
import io.sessionlayer.controlplane.grpc.v1.SessionSigningGrpc;
import io.sessionlayer.controlplane.grpc.v1.SignContext;
import io.sessionlayer.controlplane.grpc.v1.SignSessionCertificateRequest;
import io.sessionlayer.controlplane.grpc.v1.SignSessionCertificateResponse;
import io.sessionlayer.controlplane.mtls.CertificateFingerprints;
import io.sessionlayer.controlplane.mtls.MtlsContext;
import io.sessionlayer.controlplane.mtls.MtlsPeer;
import io.sessionlayer.controlplane.mtls.MtlsProperties;
import io.sessionlayer.controlplane.observability.CpTracing;
import io.sessionlayer.controlplane.observability.SloMetrics;
import java.util.UUID;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

@Service
public class SessionSigningService extends SessionSigningGrpc.SessionSigningImplBase {

	private final SessionCertificateService signing;
	private final MtlsProperties properties;
	private final CpTracing tracing;
	private final SloMetrics metrics;

	public SessionSigningService(SessionCertificateService signing, MtlsProperties properties, CpTracing tracing,
			SloMetrics metrics) {
		this.signing = signing;
		this.properties = properties;
		this.tracing = tracing;
		this.metrics = metrics;
	}

	@Override
	public void signSessionCertificate(SignSessionCertificateRequest request,
			StreamObserver<SignSessionCertificateResponse> observer) {
		MtlsPeer peer = MtlsContext.peer();
		String presentedFingerprint = CertificateFingerprints.sha256Hex(peer.certificate());
		io.opentelemetry.context.Context traceParent = CpTracing.OTEL_PARENT.get();
		String sessionId = request.hasContext() ? request.getContext().getSessionId() : null;
		Mono<SignedInnerCert> signed = Mono.fromCallable(() -> toContext(request))
				.flatMap(context -> signing.sign(peer.gatewayId(), presentedFingerprint, request.getSessionToken(),
						request.getSubjectPublicKey().toByteArray(), context));
		Mono<SignSessionCertificateResponse> result = tracing
				.traceCertSign(traceParent, "session", sessionId, metrics.timeCertSign("session", signed))
				.map(SessionSigningService::toResponse);
		ReactiveBridge.forward(result, observer, properties.getRpcTimeout(), "SignSessionCertificate");
	}

	private static SignRequestContext toContext(SignSessionCertificateRequest request) {
		if (!request.hasContext()) {
			return SignRequestContext.EMPTY;
		}
		SignContext ctx = request.getContext();
		UUID sessionId = optionalUuid(ctx.getSessionId());
		UUID nodeId = optionalUuid(ctx.getNodeId());
		String principal = ctx.getRequestedPrincipal().isBlank() ? null : ctx.getRequestedPrincipal();
		return new SignRequestContext(sessionId, nodeId, principal);
	}

	private static UUID optionalUuid(String value) {
		if (value == null || value.isBlank()) {
			return null;
		}
		try {
			return UUID.fromString(value);
		} catch (IllegalArgumentException notAUuid) {
			throw new GatewayRequestException(GatewayRequestException.Reason.PERMISSION_DENIED,
					"session signing request refused");
		}
	}

	private static SignSessionCertificateResponse toResponse(SignedInnerCert signed) {
		return SignSessionCertificateResponse.newBuilder().setCertificateLine(signed.certificateLine())
				.setCertificateBlob(ByteString.copyFrom(signed.certificateBlob())).setKeyId(signed.keyId())
				.setValidAfterEpochSeconds(signed.validAfterEpochSeconds())
				.setValidBeforeEpochSeconds(signed.validBeforeEpochSeconds()).build();
	}
}
