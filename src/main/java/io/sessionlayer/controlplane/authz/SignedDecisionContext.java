package io.sessionlayer.controlplane.authz;

import io.sessionlayer.controlplane.grpc.v1.DecisionContext;
import java.util.List;

/**
 * Signed decision context with signer cert chain for verification without new
 * trust distribution.
 */
public record SignedDecisionContext(DecisionContext context, byte[] signedContext, byte[] signature,
		byte[] signerCertificateDer, List<byte[]> caChainDer) {
}
