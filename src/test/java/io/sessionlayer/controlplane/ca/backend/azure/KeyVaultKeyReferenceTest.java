package io.sessionlayer.controlplane.ca.backend.azure;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.sessionlayer.controlplane.ca.backend.azure.KeyVaultKeyReference.InvalidKeyReference;
import org.junit.jupiter.api.Test;

/**
 * {@link KeyVaultKeyReference} is a pure security boundary — every rejection is
 * exercised in isolation so a regression names the exact clause it broke.
 */
class KeyVaultKeyReferenceTest {

	private static final String ALLOWED = "https://myvault.vault.azure.net";

	/** A well-formed Key Vault version: 32 lowercase hex characters. */
	private static final String VERSION = "abcdef0123456789abcdef0123456789";

	@Test
	void parsesAWellFormedPinnedReference() {
		KeyVaultKeyReference ref = KeyVaultKeyReference.parse("https://myvault.vault.azure.net/keys/ssh-ca/" + VERSION,
				ALLOWED);

		assertThat(ref.vaultUrl()).isEqualTo("https://myvault.vault.azure.net");
		assertThat(ref.keyName()).isEqualTo("ssh-ca");
		assertThat(ref.keyVersion()).isEqualTo(VERSION);
		assertThat(ref.keyIdentifier()).isEqualTo("https://myvault.vault.azure.net/keys/ssh-ca/" + VERSION);
	}

	@Test
	void hostComparisonIsCaseInsensitive() {
		KeyVaultKeyReference ref = KeyVaultKeyReference.parse("https://MyVault.Vault.Azure.Net/keys/ssh-ca/" + VERSION,
				ALLOWED);

		assertThat(ref.keyName()).isEqualTo("ssh-ca");
	}

	/**
	 * A default-port reference must match a configured vault-uri with no explicit
	 * port, and vice versa: both name the same vault, so treating them as different
	 * authorities would make the allow-list anchor reject a perfectly ordinary
	 * deployment.
	 */
	@Test
	void anExplicitDefaultPortMatchesAConfiguredUriWithNoPort() {
		KeyVaultKeyReference ref = KeyVaultKeyReference
				.parse("https://myvault.vault.azure.net:443/keys/ssh-ca/" + VERSION, ALLOWED);
		assertThat(ref.keyName()).isEqualTo("ssh-ca");
	}

	@Test
	void aConfiguredUriWithAnExplicitDefaultPortMatchesAPortLessReference() {
		KeyVaultKeyReference ref = KeyVaultKeyReference.parse("https://myvault.vault.azure.net/keys/ssh-ca/" + VERSION,
				"https://myvault.vault.azure.net:443");
		assertThat(ref.keyName()).isEqualTo("ssh-ca");
	}

	/**
	 * The allow-list anchor is the AUTHORITY, not just the host: on a real Azure
	 * vault the port is always 443, so a host-only comparison would look correct in
	 * every real deployment while silently accepting a reference to the same host
	 * on a different, attacker-controlled port.
	 */
	@Test
	void rejectsTheSameHostOnADifferentPort() {
		assertThatThrownBy(() -> KeyVaultKeyReference
				.parse("https://myvault.vault.azure.net:8443/keys/ssh-ca/" + VERSION, ALLOWED))
				.isInstanceOf(InvalidKeyReference.class).hasMessageContaining("only the configured vault is permitted");
	}

	@Test
	void rejectsANonHttpsUrl() {
		assertThatThrownBy(
				() -> KeyVaultKeyReference.parse("http://myvault.vault.azure.net/keys/ssh-ca/" + VERSION, ALLOWED))
				.isInstanceOf(InvalidKeyReference.class).hasMessageContaining("not a valid absolute HTTPS URL");
	}

	@Test
	void rejectsAnUnparseableUrl() {
		assertThatThrownBy(() -> KeyVaultKeyReference.parse("not a url at all", ALLOWED))
				.isInstanceOf(InvalidKeyReference.class).hasMessageContaining("not a valid absolute HTTPS URL");
	}

	@Test
	void rejectsARelativeReference() {
		assertThatThrownBy(() -> KeyVaultKeyReference.parse("/keys/ssh-ca/" + VERSION, ALLOWED))
				.isInstanceOf(InvalidKeyReference.class).hasMessageContaining("not a valid absolute HTTPS URL");
	}

	@Test
	void rejectsABlankReference() {
		assertThatThrownBy(() -> KeyVaultKeyReference.parse("", ALLOWED)).isInstanceOf(InvalidKeyReference.class);
		assertThatThrownBy(() -> KeyVaultKeyReference.parse(null, ALLOWED)).isInstanceOf(InvalidKeyReference.class);
	}

	/**
	 * Userinfo is never part of a real Key Vault identifier, and a URL carrying it
	 * is exactly the shape that has fooled a careless "starts with the trusted
	 * host" check elsewhere — refused outright rather than trusted to be parsed the
	 * same way everywhere this string travels, even though {@code java.net.URI}
	 * itself already resolves the real host correctly.
	 */
	@Test
	void rejectsAKeyReferenceCarryingUserinfo() {
		assertThatThrownBy(() -> KeyVaultKeyReference
				.parse("https://evil@myvault.vault.azure.net/keys/ssh-ca/" + VERSION, ALLOWED))
				.isInstanceOf(InvalidKeyReference.class).hasMessageContaining("must not contain userinfo");
	}

	/** The allow-list anchor — a row cannot redirect signing to another vault. */
	@Test
	void rejectsAKeyReferenceNamingADifferentVault() {
		assertThatThrownBy(() -> KeyVaultKeyReference
				.parse("https://attacker-vault.vault.azure.net/keys/ssh-ca/" + VERSION, ALLOWED))
				.isInstanceOf(InvalidKeyReference.class).hasMessageContaining("attacker-vault.vault.azure.net")
				.hasMessageContaining("only the configured vault is permitted");
	}

	@Test
	void rejectsAPathThatIsNotUnderKeys() {
		assertThatThrownBy(
				() -> KeyVaultKeyReference.parse("https://myvault.vault.azure.net/secrets/ssh-ca/" + VERSION, ALLOWED))
				.isInstanceOf(InvalidKeyReference.class).hasMessageContaining("not of the form /keys/{name}/{version}");
	}

	/**
	 * Pinning is mandatory — a version-less reference (no fourth segment at all) is
	 * refused, not defaulted. Distinct from {@link #rejectsAMalformedKeyVersion}:
	 * this is "absent", that is "present but fake" — the two rejections carry
	 * different messages so they stay distinguishable.
	 */
	@Test
	void rejectsAVersionLessReference() {
		assertThatThrownBy(() -> KeyVaultKeyReference.parse("https://myvault.vault.azure.net/keys/ssh-ca", ALLOWED))
				.isInstanceOf(InvalidKeyReference.class).hasMessageContaining("no key version")
				.hasMessageContaining("version-pinned");
	}

	/**
	 * A version-shaped-but-fake fourth segment used to satisfy the "is there a
	 * fourth segment" check without ever being a real Key Vault version (32
	 * lowercase hex characters) — low severity (a bogus version already fails
	 * closed at adoption, since {@code fetchPublicKey} gets a real 404 and the
	 * rotation aborts having written nothing), but it makes the exact-version
	 * pinning rule actually true at parse time rather than merely documented.
	 */
	@Test
	void rejectsAMalformedKeyVersion() {
		assertThatThrownBy(() -> KeyVaultKeyReference.parse("https://myvault.vault.azure.net/keys/ssh-ca/v1", ALLOWED))
				.isInstanceOf(InvalidKeyReference.class).hasMessageContaining("invalid key version");
	}

	/**
	 * A control character surviving {@code java.net.URI}'s percent-decoding used to
	 * be accepted into {@code ref.keyVersion()} unfiltered: azure-core itself
	 * percent-encodes the request path before it ever reaches the wire (so this was
	 * never HTTP request splitting), but the raw value still persisted into
	 * {@code ca_config.key_reference} and any audit diff of it, a defense-in-depth
	 * gap for a future consumer that renders the raw string outside JSON. The same
	 * allow-list that rejects {@code v1} rejects this for the same reason: neither
	 * is 32 lowercase hex characters.
	 */
	@Test
	void rejectsAControlCharacterInTheKeyVersion() {
		assertThatThrownBy(() -> KeyVaultKeyReference
				.parse("https://myvault.vault.azure.net/keys/ssh-ca/abc%0d%0aX-Injected", ALLOWED))
				.isInstanceOf(InvalidKeyReference.class).hasMessageContaining("invalid key version");
	}

	@Test
	void rejectsAnEmptyKeyName() {
		assertThatThrownBy(
				() -> KeyVaultKeyReference.parse("https://myvault.vault.azure.net/keys//" + VERSION, ALLOWED))
				.isInstanceOf(InvalidKeyReference.class).hasMessageContaining("invalid key name");
	}

	@Test
	void rejectsTrailingExtraSegments() {
		assertThatThrownBy(() -> KeyVaultKeyReference
				.parse("https://myvault.vault.azure.net/keys/ssh-ca/" + VERSION + "/extra", ALLOWED))
				.isInstanceOf(InvalidKeyReference.class).hasMessageContaining("extra segments");
	}

	/**
	 * A traversal sequence that grows the path is caught by the segment-count check
	 * above; this pins the shorter, sneakier shape where "../.." collapses the
	 * segment count back to four and would otherwise slip through as an
	 * ordinary-looking name/version.
	 */
	@Test
	void rejectsPathTraversalDisguisedAsAnOrdinaryFourSegmentPath() {
		assertThatThrownBy(() -> KeyVaultKeyReference.parse("https://myvault.vault.azure.net/keys/../ssh-ca", ALLOWED))
				.isInstanceOf(InvalidKeyReference.class);
		assertThatThrownBy(() -> KeyVaultKeyReference.parse("https://myvault.vault.azure.net/keys/ssh-ca/..", ALLOWED))
				.isInstanceOf(InvalidKeyReference.class);
	}

	@Test
	void rejectsALongerTraversalSequenceInThePath() {
		assertThatThrownBy(() -> KeyVaultKeyReference
				.parse("https://myvault.vault.azure.net/keys/ssh-ca/" + VERSION + "/../../other", ALLOWED))
				.isInstanceOf(InvalidKeyReference.class);
	}

	@Test
	void aMisconfiguredAllowedVaultUriFailsClosedAsAConfigurationBugNotAKeyReferenceProblem() {
		assertThatThrownBy(
				() -> KeyVaultKeyReference.parse("https://myvault.vault.azure.net/keys/ssh-ca/" + VERSION, "not a uri"))
				.isInstanceOf(IllegalStateException.class).hasMessageContaining("sessionlayer.ca.azure.vault-uri");
	}
}
