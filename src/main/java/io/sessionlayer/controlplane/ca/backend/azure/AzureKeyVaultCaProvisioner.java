package io.sessionlayer.controlplane.ca.backend.azure;

import io.sessionlayer.controlplane.ca.CaBackendCapabilities;
import io.sessionlayer.controlplane.ca.CaKeyProvisioner;
import io.sessionlayer.controlplane.ca.CaKeyType;
import io.sessionlayer.controlplane.data.config.CaConfig;
import io.sessionlayer.controlplane.data.runtime.CaKeyMaterial;
import java.security.interfaces.ECPublicKey;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBooleanProperty;
import org.springframework.stereotype.Component;

@Component
@ConditionalOnBooleanProperty(name = "sessionlayer.ca.azure.enabled")
public class AzureKeyVaultCaProvisioner implements CaKeyProvisioner {

	private final AzureKeyVaultSignerFactory factory;

	public AzureKeyVaultCaProvisioner(AzureKeyVaultSignerFactory factory) {
		this.factory = factory;
	}

	@Override
	public String backend() {
		return "azure_keyvault";
	}

	@Override
	public Provisioned provision(Request request) {
		CaBackendCapabilities.validate(backend(), request.algorithm());
		KeyVaultKeyReference ref = KeyVaultKeyReference.parse(request.keyReference(), factory.vaultUri());
		ECPublicKey publicKey = factory.fetchPublicKey(ref);
		CaConfig config = CaConfig.create(request.caName(), request.caKind(), backend(), ref.keyIdentifier(),
				request.algorithm(), request.rotationState(), "default");
		CaKeyMaterial material = CaKeyMaterial.createExternal(config.id(), request.caName(), publicKey.getEncoded(),
				CaKeyType.fromAlgorithmId(request.algorithm()).keyTypeName(), null);
		return new Provisioned(config, material);
	}
}
