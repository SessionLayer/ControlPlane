package io.sessionlayer.controlplane.ca.backend.azure;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.regex.Pattern;

/**
 * A parsed, validated {@code ca_config.key_reference} for the
 * {@code azure_keyvault} backend:
 * {@code https://<vault>/keys/<name>/<version>}. Parsing is pure — no network
 * access — so the two security properties it enforces are testable without a
 * vault:
 *
 * <ul>
 * <li><b>Pinned.</b> A version-less reference is refused: floating the signing
 * key underneath a running CA would silently start emitting certificates no
 * node trusts, since the CA's public half is already distributed to every
 * node's trusted set at the pinned version. The version segment is also
 * allow-listed to Key Vault's real grammar (32 lowercase hex characters), not
 * merely required to be present — a present-but-fake value like {@code v1} used
 * to satisfy the "is there a fourth segment" check without ever being a real
 * Key Vault version.</li>
 * <li><b>Allow-listed authority.</b> The reference's authority (scheme, host,
 * and port, with default-port normalization) must equal the configured
 * {@code sessionlayer.ca.azure.vault-uri}; a {@code ca_config} row cannot
 * redirect signing to a vault the operator did not configure — the anchor lives
 * in process configuration, which a compromised database row cannot reach.</li>
 * <li><b>Allow-listed name/version characters.</b> Both segments are matched
 * against Key Vault's own naming grammar rather than merely excluded from a few
 * known-bad shapes (blank, {@code .}/{@code ..}) — a control character
 * surviving {@code java.net.URI}'s percent-decoding has nowhere to hide in a
 * value nothing downstream re-escapes.</li>
 * </ul>
 */
public final class KeyVaultKeyReference {

	private static final int HTTPS_DEFAULT_PORT = 443;

	/** Azure Key Vault key names: letters, digits, and hyphens. */
	private static final Pattern KEY_NAME = Pattern.compile("[0-9A-Za-z-]+");

	/** Azure Key Vault key versions: exactly 32 lowercase hex characters. */
	private static final Pattern KEY_VERSION = Pattern.compile("[0-9a-f]{32}");

	private final String vaultUrl;
	private final String keyName;
	private final String keyVersion;

	private KeyVaultKeyReference(String vaultUrl, String keyName, String keyVersion) {
		this.vaultUrl = vaultUrl;
		this.keyName = keyName;
		this.keyVersion = keyVersion;
	}

	/** Refused for every way a {@code key_reference} can fail validation. */
	public static final class InvalidKeyReference extends RuntimeException {
		public InvalidKeyReference(String message) {
			super(message);
		}
	}

	public static KeyVaultKeyReference parse(String keyReference, String allowedVaultUri) {
		if (keyReference == null || keyReference.isBlank()) {
			throw new InvalidKeyReference("CA key_reference is empty");
		}
		URI uri = parseAbsoluteHttps(keyReference);
		if (uri.getRawUserInfo() != null) {
			// Not a shape Key Vault ever produces, and a URL with userinfo in the
			// authority is exactly the pattern that has fooled naive host checks
			// elsewhere (the part before '@' looks like a host to a careless
			// reader/parser even though java.net.URI resolves the real one
			// correctly) — refused outright rather than trusted to parse the same
			// way everywhere this string travels.
			throw new InvalidKeyReference("CA key_reference '" + keyReference + "' must not contain userinfo");
		}
		URI allowed = parseAllowedVaultUri(allowedVaultUri);
		if (!sameAuthority(allowed, uri)) {
			throw new InvalidKeyReference("CA key_reference authority '" + uri.getAuthority()
					+ "' is not the configured Key Vault (sessionlayer.ca.azure.vault-uri '" + allowed.getAuthority()
					+ "') — only the configured vault is permitted");
		}
		String[] segments = splitPath(uri, keyReference);
		if (!"keys".equals(segments[1])) {
			throw new InvalidKeyReference(
					"CA key_reference path '" + uri.getRawPath() + "' is not of the form /keys/{name}/{version}");
		}
		String name = segments[2];
		if (!KEY_NAME.matcher(name).matches()) {
			throw new InvalidKeyReference("CA key_reference '" + keyReference + "' has an invalid key name");
		}
		if (segments.length < 4) {
			throw new InvalidKeyReference("CA key_reference '" + keyReference
					+ "' has no key version — Key Vault CA keys must be version-pinned, so a floating reference is"
					+ " refused rather than resolved to whatever it would normalize to");
		}
		if (!KEY_VERSION.matcher(segments[3]).matches()) {
			throw new InvalidKeyReference("CA key_reference '" + keyReference
					+ "' has an invalid key version — a real Key Vault version is 32 lowercase hex characters, and a"
					+ " value that merely occupies the version position (present but not a real version) is refused"
					+ " the same as one that is absent");
		}
		if (segments.length > 4) {
			throw new InvalidKeyReference(
					"CA key_reference path '" + uri.getRawPath() + "' has unexpected extra segments");
		}
		// Preserved as written (not port-normalized): this is what is handed to the
		// Key Vault SDK as the vault URL, and Key Vault identifiers never carry an
		// explicit default port, so there is no reason to introduce one here. Only
		// the authority COMPARISON above is port-normalized.
		String vaultUrl = uri.getScheme() + "://" + uri.getHost() + (uri.getPort() == -1 ? "" : ":" + uri.getPort());
		return new KeyVaultKeyReference(vaultUrl, name, segments[3]);
	}

	private static boolean sameAuthority(URI allowed, URI reference) {
		if (!"https".equalsIgnoreCase(reference.getScheme()) || !"https".equalsIgnoreCase(allowed.getScheme())) {
			return false;
		}
		if (!allowed.getHost().equalsIgnoreCase(reference.getHost())) {
			return false;
		}
		return normalizedPort(allowed) == normalizedPort(reference);
	}

	// A configured vault-uri with no explicit port and a key_reference pinning
	// the default HTTPS port (or vice versa) name the same vault; comparing raw
	// getPort() values would treat "https://v" and "https://v:443" as different
	// authorities, which is not the guarantee this anchor is supposed to give.
	private static int normalizedPort(URI uri) {
		return uri.getPort() == -1 ? HTTPS_DEFAULT_PORT : uri.getPort();
	}

	private static URI parseAbsoluteHttps(String keyReference) {
		URI uri;
		try {
			uri = new URI(keyReference);
		} catch (URISyntaxException e) {
			throw new InvalidKeyReference("CA key_reference '" + keyReference + "' is not a valid absolute HTTPS URL");
		}
		if (!uri.isAbsolute() || uri.getHost() == null || uri.getHost().isBlank()
				|| !"https".equalsIgnoreCase(uri.getScheme())) {
			throw new InvalidKeyReference("CA key_reference '" + keyReference + "' is not a valid absolute HTTPS URL");
		}
		return uri;
	}

	private static URI parseAllowedVaultUri(String allowedVaultUri) {
		try {
			URI allowed = new URI(allowedVaultUri);
			if (allowed.getHost() == null) {
				throw new URISyntaxException(allowedVaultUri, "no host");
			}
			return allowed;
		} catch (URISyntaxException e) {
			// AzureKeyVaultProperties already refuses to start with an unusable
			// vault-uri, so reaching here means that guard was bypassed, not a bad
			// key_reference.
			throw new IllegalStateException(
					"sessionlayer.ca.azure.vault-uri '" + allowedVaultUri + "' is not a usable absolute URI", e);
		}
	}

	private static String[] splitPath(URI uri, String keyReference) {
		String path = uri.getPath();
		// A leading "/keys/..." splits to ["", "keys", name, version, ...]. Not
		// normalized: a ".."-bearing path either grows past 4 segments (caught
		// below) or survives as a literal ".."/"." name or version, which the
		// KEY_NAME/KEY_VERSION allow-list below rejects (neither character is in
		// either pattern) — it is never silently resolved into a different key.
		String[] segments = (path == null ? "" : path).split("/");
		if (segments.length < 3) {
			throw new InvalidKeyReference(
					"CA key_reference '" + keyReference + "' path is not of the form /keys/{name}/{version}");
		}
		return segments;
	}

	public String vaultUrl() {
		return vaultUrl;
	}

	public String keyName() {
		return keyName;
	}

	public String keyVersion() {
		return keyVersion;
	}

	public String keyIdentifier() {
		return vaultUrl + "/keys/" + keyName + "/" + keyVersion;
	}
}
