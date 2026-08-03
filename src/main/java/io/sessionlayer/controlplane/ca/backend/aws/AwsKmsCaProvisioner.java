package io.sessionlayer.controlplane.ca.backend.aws;

import io.sessionlayer.controlplane.ca.CaBackendCapabilities;
import io.sessionlayer.controlplane.ca.CaKeyProvisioner;
import io.sessionlayer.controlplane.ca.CaKeyType;
import io.sessionlayer.controlplane.data.config.CaConfig;
import io.sessionlayer.controlplane.data.runtime.CaKeyMaterial;
import java.security.interfaces.ECPublicKey;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

/**
 * Adopts an existing KMS key as a CA: the rotation-time bridge between
 * {@link KmsKeyArn} (write-path validation) and
 * {@link AwsKmsSignerFactory#fetchPublicKey} (the one KMS read this whole seam
 * performs). Present only when {@code sessionlayer.ca.aws.enabled=true} — its
 * absence is the same "not configured" branch {@link AwsKmsSignerFactory}'s
 * absence is for signing, so {@code CaRotationService.NoProvisionerForBackend}
 * is the correct refusal on a Control Plane with no KMS support, not a fallback
 * to a database key.
 */
@Component
@ConditionalOnProperty(prefix = "sessionlayer.ca.aws", name = "enabled", havingValue = "true")
public class AwsKmsCaProvisioner implements CaKeyProvisioner {

	private final AwsKmsSignerFactory factory;

	public AwsKmsCaProvisioner(AwsKmsSignerFactory factory) {
		this.factory = factory;
	}

	@Override
	public String backend() {
		return "aws_kms";
	}

	/**
	 * Refuses an alias, a bare key id, or an ARN outside the configured
	 * account/region/partition before ever calling KMS (the write-path enforcement
	 * of the pinning and allow-list anchor), then resolves the key's public half —
	 * the one network call this makes, and the one point a CA's whole trust chain
	 * is rooted at, so a mismatched or wrong-shaped key fails here rather than
	 * getting silently adopted.
	 */
	@Override
	public Provisioned provision(Request request) {
		CaBackendCapabilities.validate(backend(), request.algorithm());
		KmsKeyArn ref = KmsKeyArn.parse(request.keyReference(), factory.anchor());
		ECPublicKey publicKey = factory.fetchPublicKey(ref);
		CaConfig config = CaConfig.create(request.caName(), request.caKind(), backend(), ref.keyArn(),
				request.algorithm(), request.rotationState(), "default");
		CaKeyMaterial material = CaKeyMaterial.createExternal(config.id(), request.caName(), publicKey.getEncoded(),
				CaKeyType.fromAlgorithmId(request.algorithm()).keyTypeName(), null);
		return new Provisioned(config, material);
	}
}
