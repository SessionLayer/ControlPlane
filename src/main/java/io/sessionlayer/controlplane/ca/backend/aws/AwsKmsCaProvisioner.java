package io.sessionlayer.controlplane.ca.backend.aws;

import io.sessionlayer.controlplane.ca.CaBackendCapabilities;
import io.sessionlayer.controlplane.ca.CaKeyProvisioner;
import io.sessionlayer.controlplane.ca.CaKeyType;
import io.sessionlayer.controlplane.data.config.CaConfig;
import io.sessionlayer.controlplane.data.runtime.CaKeyMaterial;
import java.security.interfaces.ECPublicKey;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBooleanProperty;
import org.springframework.stereotype.Component;

@Component
@ConditionalOnBooleanProperty(name = "sessionlayer.ca.aws.enabled")
public class AwsKmsCaProvisioner implements CaKeyProvisioner {

	private final AwsKmsSignerFactory factory;

	public AwsKmsCaProvisioner(AwsKmsSignerFactory factory) {
		this.factory = factory;
	}

	@Override
	public String backend() {
		return "aws_kms";
	}

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
