package io.sessionlayer.controlplane.ca.backend.azure;

import io.sessionlayer.controlplane.ca.CaBackendCapabilities;
import io.sessionlayer.controlplane.ca.CaKeyProvisioner;
import io.sessionlayer.controlplane.ca.CaKeyType;
import io.sessionlayer.controlplane.data.config.CaConfig;
import io.sessionlayer.controlplane.data.runtime.CaKeyMaterial;
import java.security.interfaces.ECPublicKey;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

/**
 * Adopts an existing Key Vault key as a CA: the rotation-time bridge between
 * {@link KeyVaultKeyReference} (write-path validation) and
 * {@link AzureKeyVaultSignerFactory#fetchPublicKey} (the one vault read this
 * whole seam performs). Present only when
 * {@code sessionlayer.ca.azure.enabled=true} — its absence is the same "not
 * configured" branch {@link AzureKeyVaultSignerFactory}'s absence is for
 * signing, so {@code CaRotationService.NoProvisionerForBackend} is the correct
 * refusal on a Control Plane with no Key Vault support, not a fallback to a
 * database key.
 */
@Component
@ConditionalOnProperty(prefix = "sessionlayer.ca.azure", name = "enabled", havingValue = "true")
public class AzureKeyVaultCaProvisioner implements CaKeyProvisioner {

	private final AzureKeyVaultSignerFactory factory;

	public AzureKeyVaultCaProvisioner(AzureKeyVaultSignerFactory factory) {
		this.factory = factory;
	}

	@Override
	public String backend() {
		return "azure_keyvault";
	}

	/**
	 * Refuses an unversioned or wrong-vault {@code keyReference} before ever
	 * calling the vault (the write-path enforcement of the pinning and allow-list
	 * anchor), then resolves the key's public half — the one network call this
	 * makes, and the one point a CA's whole trust chain is rooted at, so a
	 * mismatched or wrong-shaped key fails here rather than getting silently
	 * adopted.
	 */
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
