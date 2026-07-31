package io.sessionlayer.controlplane.ca;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class CaBackendCapabilitiesTest {

	@Test
	void localAndAzureKeyVaultSignAsShipped() {
		assertThatCode(() -> CaBackendCapabilities.validate("local", "ecdsa-p256")).doesNotThrowAnyException();
		assertThatCode(() -> CaBackendCapabilities.validate("azure_keyvault", "ecdsa-p256")).doesNotThrowAnyException();
	}

	/**
	 * {@code aws_kms} and {@code vault} are integration seams: their classes
	 * consume interfaces nothing in this build implements, no bean constructs them,
	 * and {@code CaSignerService.signerFor} refuses both before per-backend
	 * dispatch is reached. Accepting either stores a CA that cannot issue a single
	 * certificate — fleet-wide, since the session CA gates every new session.
	 * {@code azure_keyvault} is no longer one of these: it has a real, bean-backed
	 * signer.
	 *
	 * <p>
	 * A first version of this rule refused only {@code vault} and named the other
	 * two as alternatives, which was worse than not having it: the refusal read as
	 * a verified allowlist and steered an operator from one unusable backend to
	 * another with the platform's endorsement. {@code azure_keyvault} is exempt
	 * from that concern now that it genuinely works — see
	 * {@link #theRefusalNamesTheRealAlternativesButNeverTheOtherStillUnusableBackend}.
	 */
	@ParameterizedTest
	@ValueSource(strings = {"vault", "aws_kms"})
	void theRemainingKeyServiceBackendsAreRefusedBecauseNeitherHasASigner(String backend) {
		assertThatThrownBy(() -> CaBackendCapabilities.validate(backend, "ecdsa-p256"))
				.isInstanceOf(CaBackendCapabilities.BackendNotImplemented.class).hasMessageContaining(backend)
				.hasMessageContaining("no signer in this build");
	}

	/**
	 * The refusal must name the backends that genuinely work ('local',
	 * 'azure_keyvault') without ever naming the OTHER still-unusable backend as
	 * though it were an alternative — refusing 'vault' must not mention 'aws_kms'
	 * and vice versa. This is the assertion the first version of this rule would
	 * have failed.
	 */
	@Test
	void theRefusalNamesTheRealAlternativesButNeverTheOtherStillUnusableBackend() {
		String vaultMessage = assertThatThrownBy(() -> CaBackendCapabilities.validate("vault", "ecdsa-p256")).actual()
				.getMessage();
		// "'vault'" (quoted), not "vault": azure_keyvault legitimately contains "vault"
		// as a substring, and that is the real alternative being named, not a leak.
		assertThat(vaultMessage).doesNotContain("'aws_kms'").contains("'local'").contains("'azure_keyvault'");

		String kmsMessage = assertThatThrownBy(() -> CaBackendCapabilities.validate("aws_kms", "ecdsa-p256")).actual()
				.getMessage();
		assertThat(kmsMessage).doesNotContain("'vault'").contains("'local'").contains("'azure_keyvault'");
	}

	/**
	 * The write path and the signer must ask the SAME question, or a backend the
	 * API accepts and one that can sign become different sets — which is the defect
	 * this class exists to prevent, one level up.
	 */
	@Test
	void theImplementedPredicateIsTheOneTheSignerAsks() {
		assertThat(CaBackendCapabilities.isImplemented("local")).isTrue();
		assertThat(CaBackendCapabilities.isImplemented("azure_keyvault")).isTrue();
		for (String seam : new String[]{"vault", "aws_kms"}) {
			assertThat(CaBackendCapabilities.isImplemented(seam)).as(seam).isFalse();
		}
	}

	/**
	 * The per-backend algorithm table is still asserted directly rather than
	 * through {@code validate}, which no longer reaches it for a key-service
	 * backend that lacks a signer. It describes what each seam could sign once
	 * wired, so it has to stay correct for whoever wires one.
	 */
	@Test
	void theCapabilityTableStillDescribesWhatEachSeamCouldSign() {
		assertThat(CaBackendCapabilities.forBackend("local").supports("ecdsa-p384")).isTrue();
		assertThat(CaBackendCapabilities.forBackend("local").supports("ecdsa-p521")).isTrue();
		for (String cloud : new String[]{"aws_kms", "azure_keyvault", "vault"}) {
			assertThat(CaBackendCapabilities.forBackend(cloud).supports("ecdsa-p256")).as(cloud).isTrue();
			assertThat(CaBackendCapabilities.forBackend(cloud).supports("ecdsa-p384")).as(cloud).isFalse();
		}
	}

	@Test
	void nonEcdsaAlgorithmsAreRejectedOnTheBackendsThatDoSign() {
		assertThatThrownBy(() -> CaBackendCapabilities.validate("local", "rsa-4096"))
				.isInstanceOf(CaBackendCapabilities.AlgorithmNotSupported.class);
		assertThatThrownBy(() -> CaBackendCapabilities.validate("local", "ed25519"))
				.isInstanceOf(CaBackendCapabilities.AlgorithmNotSupported.class);
		assertThatThrownBy(() -> CaBackendCapabilities.validate("azure_keyvault", "ed25519"))
				.isInstanceOf(CaBackendCapabilities.AlgorithmNotSupported.class);
		assertThatThrownBy(() -> CaBackendCapabilities.validate("azure_keyvault", "ecdsa-p384"))
				.isInstanceOf(CaBackendCapabilities.AlgorithmNotSupported.class);
	}

	@Test
	void unknownBackendIsRejected() {
		assertThatThrownBy(() -> CaBackendCapabilities.validate("sqlite", "ecdsa-p256"))
				.isInstanceOf(IllegalArgumentException.class);
		assertThatThrownBy(() -> CaBackendCapabilities.isImplemented("sqlite"))
				.isInstanceOf(IllegalArgumentException.class);
	}
}
