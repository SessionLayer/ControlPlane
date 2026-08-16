package io.sessionlayer.controlplane.ca;

import io.sessionlayer.controlplane.ca.backend.aws.AwsKmsSignerFactory;
import io.sessionlayer.controlplane.ca.backend.aws.KmsCaBackend;
import io.sessionlayer.controlplane.ca.backend.aws.KmsKeyArn;
import io.sessionlayer.controlplane.ca.backend.aws.KmsSigner;
import io.sessionlayer.controlplane.ca.backend.azure.AzureKeyVaultCaBackend;
import io.sessionlayer.controlplane.ca.backend.azure.AzureKeyVaultSignerFactory;
import io.sessionlayer.controlplane.ca.backend.azure.KeyVaultKeyReference;
import io.sessionlayer.controlplane.ca.backend.azure.KeyVaultSigner;
import io.sessionlayer.controlplane.data.config.CaConfig;
import io.sessionlayer.controlplane.data.config.CaConfigRepository;
import io.sessionlayer.controlplane.data.runtime.CaKeyMaterial;
import io.sessionlayer.controlplane.data.runtime.CaKeyMaterialRepository;
import io.sessionlayer.controlplane.observability.SloMetrics;
import java.security.KeyFactory;
import java.security.interfaces.ECPublicKey;
import java.security.spec.X509EncodedKeySpec;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

@Service
public class CaSignerService {

	private final CaConfigRepository caConfigs;
	private final CaKeyMaterialRepository caKeyMaterials;
	private final LocalCaFactory localCaFactory;
	private final SloMetrics metrics;
	private final ObjectProvider<AzureKeyVaultSignerFactory> azureSignerFactory;
	private final ObjectProvider<AwsKmsSignerFactory> awsKmsSignerFactory;

	public CaSignerService(CaConfigRepository caConfigs, CaKeyMaterialRepository caKeyMaterials,
			LocalCaFactory localCaFactory, SloMetrics metrics,
			ObjectProvider<AzureKeyVaultSignerFactory> azureSignerFactory,
			ObjectProvider<AwsKmsSignerFactory> awsKmsSignerFactory) {
		this.caConfigs = caConfigs;
		this.caKeyMaterials = caKeyMaterials;
		this.localCaFactory = localCaFactory;
		this.metrics = metrics;
		this.azureSignerFactory = azureSignerFactory;
		this.awsKmsSignerFactory = awsKmsSignerFactory;
	}

	public static final class NoSignerAvailable extends RuntimeException {
		public NoSignerAvailable(String message) {
			super(message);
		}
	}

	public Mono<SshCertSigner> activeSigner(String kind) {
		return activeSigner(kind, SloMetrics.SOURCE_REQUEST);
	}

	public Mono<SshCertSigner> activeSigner(String kind, String source) {
		return caConfigs.findByCaKindAndRotationState(kind, "active")
				.switchIfEmpty(Mono.error(new NoSignerAvailable("no active " + kind + " CA (fail closed)")))
				.flatMap(this::signerFor).doOnSuccess(signer -> {
					if (signer != null) {
						metrics.recordSignerOutcome(kind, source, "available");
					}
				}).doOnError(error -> metrics.recordSignerOutcome(kind, source,
						error instanceof NoSignerAvailable ? "unavailable" : "error"));
	}

	public Mono<SshCertSigner> signerFor(CaConfig config) {
		return Mono.defer(() -> {
			// Same predicate the write path refuses on (CaBackendCapabilities.validate),
			// so a backend the API accepts and one this can sign with cannot become
			// different sets. This also refuses vault before dispatch is reached — it
			// has a class but no bean, so isImplemented is false for it.
			CaBackendCapabilities.validate(config.backend(), config.algorithm());
			return switch (config.backend()) {
				case "local" -> localSigner(config);
				case "azure_keyvault" -> azureSigner(config);
				case "aws_kms" -> awsKmsSigner(config);
				// Defensive only: CaBackendCapabilities.isImplemented, checked above by
				// validate(), is the single source of truth for which backends reach here —
				// a backend flipped true there with no case added here must still fail
				// closed, never fall through to local.
				default -> Mono.error(new NoSignerAvailable(
						"CA backend '" + config.backend() + "' has no dispatch wired in CaSignerService"));
			};
		});
	}

	private Mono<SshCertSigner> localSigner(CaConfig config) {
		return caKeyMaterials.findByCaConfigId(config.id())
				.switchIfEmpty(Mono.error(new NoSignerAvailable("local CA key material missing for " + config.name())))
				.map(material -> localCaFactory.load(config, material));
	}

	// No path here ever reaches localCaFactory: a CA the operator configured for
	// Key Vault must never silently sign from the database instead. A missing
	// bean / malformed key_reference / missing key material all fail closed as
	// NoSignerAvailable; an actual vault I/O failure (unreachable, credential
	// rejected, key disabled) propagates unwrapped from AzureKeyVaultSigner at
	// sign time.
	private Mono<SshCertSigner> azureSigner(CaConfig config) {
		AzureKeyVaultSignerFactory factory = azureSignerFactory.getIfAvailable();
		if (factory == null) {
			return Mono.error(new NoSignerAvailable("CA '" + config.name()
					+ "' is configured for Key Vault (backend=azure_keyvault) but this Control Plane has no Key"
					+ " Vault support configured (set sessionlayer.ca.azure.enabled=true and vault-uri)"));
		}
		return caKeyMaterials.findByCaConfigId(config.id())
				.switchIfEmpty(
						Mono.error(new NoSignerAvailable("Key Vault CA key material missing for " + config.name())))
				.flatMap(material -> {
					try {
						return Mono.just(buildAzureSigner(config, material, factory));
					} catch (RuntimeException malformed) {
						return Mono.error(new NoSignerAvailable("CA '" + config.name()
								+ "' has an unusable Key Vault configuration: " + malformed.getMessage()));
					}
				});
	}

	private Mono<SshCertSigner> awsKmsSigner(CaConfig config) {
		AwsKmsSignerFactory factory = awsKmsSignerFactory.getIfAvailable();
		if (factory == null) {
			return Mono.error(new NoSignerAvailable("CA '" + config.name()
					+ "' is configured for AWS KMS (backend=aws_kms) but this Control Plane has no KMS support"
					+ " configured (set sessionlayer.ca.aws.enabled=true, region and account-id)"));
		}
		return caKeyMaterials.findByCaConfigId(config.id())
				.switchIfEmpty(Mono.error(new NoSignerAvailable("KMS CA key material missing for " + config.name())))
				.flatMap(material -> {
					try {
						return Mono.just(buildAwsKmsSigner(config, material, factory));
					} catch (KmsKeyArn.InvalidKeyReference malformed) {
						// The rule, never the reference. Here the string is the STORED
						// key_reference, not the caller's own submission, and this message is
						// logged on every certificate request the CA takes — so echoing it
						// would write the AWS account id into the log at request volume. The
						// 422 on the write path is where an operator sees their own value.
						return Mono.error(new NoSignerAvailable(
								"CA '" + config.name() + "' has an unusable KMS key_reference: " + malformed.rule()));
					} catch (RuntimeException malformed) {
						return Mono.error(
								new NoSignerAvailable("CA '" + config.name() + "' has an unusable KMS configuration ("
										+ malformed.getClass().getSimpleName() + ")"));
					}
				});
	}

	private static SshCertSigner buildAwsKmsSigner(CaConfig config, CaKeyMaterial material,
			AwsKmsSignerFactory factory) {
		ECPublicKey pinnedPublicKey = decodePublicKey(material);
		KmsKeyArn ref = KmsKeyArn.parse(config.keyReference(), factory.anchor());
		KmsSigner signer = factory.signerFor(ref, pinnedPublicKey);
		return new RawSignerCertSigner(new KmsCaBackend(CaKeyType.fromAlgorithmId(config.algorithm()), signer));
	}

	private static SshCertSigner buildAzureSigner(CaConfig config, CaKeyMaterial material,
			AzureKeyVaultSignerFactory factory) {
		ECPublicKey pinnedPublicKey = decodePublicKey(material);
		KeyVaultKeyReference ref = KeyVaultKeyReference.parse(config.keyReference(), factory.vaultUri());
		KeyVaultSigner signer = factory.signerFor(ref, pinnedPublicKey);
		return new RawSignerCertSigner(
				new AzureKeyVaultCaBackend(CaKeyType.fromAlgorithmId(config.algorithm()), signer));
	}

	private static ECPublicKey decodePublicKey(CaKeyMaterial material) {
		try {
			return (ECPublicKey) KeyFactory.getInstance("EC")
					.generatePublic(new X509EncodedKeySpec(material.publicKey()));
		} catch (Exception e) {
			throw new IllegalStateException("stored CA public key is not a valid EC key", e);
		}
	}
}
