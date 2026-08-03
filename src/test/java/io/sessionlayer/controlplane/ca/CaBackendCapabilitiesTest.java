package io.sessionlayer.controlplane.ca;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.LinkedHashSet;
import java.util.Set;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class CaBackendCapabilitiesTest {

	@ParameterizedTest
	@ValueSource(strings = {"local", "azure_keyvault", "aws_kms"})
	void theseBackendsSignAsShipped(String backend) {
		assertThatCode(() -> CaBackendCapabilities.validate(backend, "ecdsa-p256")).doesNotThrowAnyException();
	}

	/**
	 * {@code vault} is an integration seam: its class consumes an interface nothing
	 * in this build implements, no bean constructs it, and
	 * {@code CaSignerService.signerFor} refuses it before per-backend dispatch is
	 * reached. Accepting it stores a CA that cannot issue a single certificate —
	 * fleet-wide, since the session CA gates every new session.
	 */
	@Test
	void vaultIsRefusedBecauseItHasNoSigner() {
		assertThatThrownBy(() -> CaBackendCapabilities.validate("vault", "ecdsa-p256"))
				.isInstanceOf(CaBackendCapabilities.BackendNotImplemented.class).hasMessageContaining("vault")
				.hasMessageContaining("no signer in this build");
	}

	/**
	 * The refusal names alternatives, which reads as a verified allowlist — so
	 * every backend it names has to be one that genuinely signs. An earlier version
	 * steered an operator from one unusable backend to another with the platform's
	 * endorsement. Checked against {@code isImplemented} rather than a literal
	 * list, so adding a seam and naming it here fails this test instead of shipping
	 * the same defect.
	 */
	@Test
	void everyAlternativeTheRefusalNamesIsABackendThatActuallySigns() {
		String message = assertThatThrownBy(() -> CaBackendCapabilities.validate("vault", "ecdsa-p256")).actual()
				.getMessage();

		// Quoting is what makes this checkable: azure_keyvault legitimately contains
		// "vault" as a substring, so a bare-substring search cannot tell the refused
		// backend from an alternative that happens to spell it.
		Set<String> named = Pattern.compile("'([a-z_]+)'").matcher(message).results().map(match -> match.group(1))
				.collect(Collectors.toCollection(LinkedHashSet::new));

		assertThat(named).as("the refusal must name the backend it refused").contains("vault");
		named.remove("vault");
		assertThat(named).as("the refusal must offer a way forward").isNotEmpty();
		for (String alternative : named) {
			assertThat(CaBackendCapabilities.isImplemented(alternative)).as(alternative).isTrue();
		}
	}

	/**
	 * The write path and the signer must ask the SAME question, or a backend the
	 * API accepts and one that can sign become different sets — which is the defect
	 * this class exists to prevent, one level up.
	 */
	@Test
	void theImplementedPredicateIsTheOneTheSignerAsks() {
		for (String signs : new String[]{"local", "azure_keyvault", "aws_kms"}) {
			assertThat(CaBackendCapabilities.isImplemented(signs)).as(signs).isTrue();
		}
		assertThat(CaBackendCapabilities.isImplemented("vault")).isFalse();
	}

	/**
	 * The per-backend algorithm table is still asserted directly rather than
	 * through {@code validate}, which no longer reaches it for {@code vault}. It
	 * describes what that seam could sign once wired, so it has to stay correct for
	 * whoever wires it.
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
		assertThatThrownBy(() -> CaBackendCapabilities.validate("aws_kms", "ed25519"))
				.isInstanceOf(CaBackendCapabilities.AlgorithmNotSupported.class);
		assertThatThrownBy(() -> CaBackendCapabilities.validate("aws_kms", "ecdsa-p384"))
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
