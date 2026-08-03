package io.sessionlayer.controlplane.ca.backend.aws;

import java.util.regex.Pattern;

/**
 * A parsed, validated {@code ca_config.key_reference} for the {@code aws_kms}
 * backend: {@code arn:<partition>:kms:<region>:<account-id>:key/<key-id>}.
 * Parsing is pure — no network access — so the security properties it enforces
 * are testable without KMS:
 *
 * <ul>
 * <li><b>Pinned.</b> Only a key ARN is accepted. An <b>alias</b> — in ARN form
 * or bare — is refused: {@code kms:UpdateAlias} repoints an alias to a
 * different key without touching anything SessionLayer can see, so a CA
 * referencing one would silently start signing with a key whose public half is
 * in no node's {@code TrustedUserCAKeys}. KMS asymmetric key material never
 * rotates (key rotation is symmetric-only), so a key ARN is itself the pinned
 * version — there is no version segment to require.</li>
 * <li><b>Full ARN required.</b> A bare key id carries no partition, region or
 * account, so the anchor below could not be applied and the reference would
 * resolve against whatever the process happens to be pointed at.</li>
 * <li><b>Allow-listed anchor.</b> The ARN's partition, region and account id
 * must equal the configured {@code sessionlayer.ca.aws.*} values; a
 * {@code ca_config} row written by a compromised database cannot redirect
 * signing to another account, region or partition, because the anchor lives in
 * process configuration.</li>
 * <li><b>Allow-listed key-id characters.</b> The key id is matched against the
 * two shapes KMS actually issues rather than merely required to be non-empty —
 * a value that occupies the position without being a real key id has nowhere to
 * hide in a string that is persisted and later rendered in audit diffs.</li>
 * </ul>
 */
public final class KmsKeyArn {

	private static final String KEY_RESOURCE_PREFIX = "key/";

	private static final String ALIAS_RESOURCE_PREFIX = "alias/";

	/** A single-Region key id (a UUID) or a multi-Region key id. */
	private static final Pattern KEY_ID = Pattern
			.compile("[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|mrk-[0-9a-f]{32}");

	private static final Pattern REGION = Pattern.compile("[a-z0-9-]+");

	private static final Pattern ACCOUNT_ID = Pattern.compile("[0-9]{12}");

	private static final Pattern PARTITION = Pattern.compile("aws|aws-us-gov|aws-cn");

	/** The number of colon-separated fields in an ARN. */
	private static final int ARN_FIELDS = 6;

	private final Anchor anchor;
	private final String keyId;

	private KmsKeyArn(Anchor anchor, String keyId) {
		this.anchor = anchor;
		this.keyId = keyId;
	}

	/**
	 * The account, region and partition a {@code key_reference} is required to name
	 * — {@code sessionlayer.ca.aws.*}, read from process configuration rather than
	 * from anything a database row can influence.
	 */
	public record Anchor(String partition, String region, String accountId) {
		public Anchor {
			// AwsKmsProperties already refuses to start with any of these missing or
			// malformed, so reaching here means that guard was bypassed, not that a
			// key_reference is bad.
			require(partition, PARTITION, "partition");
			require(region, REGION, "region");
			require(accountId, ACCOUNT_ID, "account-id");
		}

		private static void require(String value, Pattern shape, String property) {
			if (value == null || !shape.matcher(value).matches()) {
				throw new IllegalStateException(
						"sessionlayer.ca.aws." + property + " '" + value + "' is not a usable value");
			}
		}
	}

	/** Refused for every way a {@code key_reference} can fail validation. */
	public static final class InvalidKeyReference extends RuntimeException {
		public InvalidKeyReference(String message) {
			super(message);
		}
	}

	public static KmsKeyArn parse(String keyReference, Anchor anchor) {
		if (keyReference == null || keyReference.isBlank()) {
			throw new InvalidKeyReference("CA key_reference is empty");
		}
		if (keyReference.startsWith(ALIAS_RESOURCE_PREFIX)) {
			throw aliasRefused(keyReference);
		}
		String[] fields = keyReference.split(":", -1);
		if (fields.length != ARN_FIELDS || !"arn".equals(fields[0])) {
			throw new InvalidKeyReference("CA key_reference '" + keyReference
					+ "' is not a KMS key ARN — a bare key id or a partial reference carries no account, region or"
					+ " partition to check, so the full arn:<partition>:kms:<region>:<account-id>:key/<key-id> is"
					+ " required");
		}
		if (!"kms".equals(fields[2])) {
			throw new InvalidKeyReference(
					"CA key_reference '" + keyReference + "' names the '" + fields[2] + "' service, not 'kms'");
		}
		String resource = fields[5];
		if (resource.startsWith(ALIAS_RESOURCE_PREFIX)) {
			throw aliasRefused(keyReference);
		}
		if (!resource.startsWith(KEY_RESOURCE_PREFIX)) {
			throw new InvalidKeyReference(
					"CA key_reference '" + keyReference + "' resource is not of the form key/{key-id}");
		}
		String keyId = resource.substring(KEY_RESOURCE_PREFIX.length());
		if (!KEY_ID.matcher(keyId).matches()) {
			throw new InvalidKeyReference("CA key_reference '" + keyReference
					+ "' has an invalid key id — a KMS key id is a UUID or a multi-Region 'mrk-' id, and a value that"
					+ " merely occupies the key-id position is refused the same as one that is absent");
		}
		requireAnchored(keyReference, anchor.partition(), fields[1], "partition");
		requireAnchored(keyReference, anchor.region(), fields[3], "region");
		requireAnchored(keyReference, anchor.accountId(), fields[4], "account-id");
		return new KmsKeyArn(anchor, keyId);
	}

	private static void requireAnchored(String keyReference, String configured, String referenced, String property) {
		if (!configured.equals(referenced)) {
			throw new InvalidKeyReference("CA key_reference '" + keyReference + "' names " + property + " '"
					+ referenced + "', not the configured sessionlayer.ca.aws." + property + " '" + configured
					+ "' — only the configured account, region and partition are permitted");
		}
	}

	private static InvalidKeyReference aliasRefused(String keyReference) {
		return new InvalidKeyReference("CA key_reference '" + keyReference
				+ "' is a KMS alias — an alias can be repointed at a different key with no change visible here, which"
				+ " would silently swap the CA's signing key while every node still trusts the old public half. Use"
				+ " the key ARN.");
	}

	/**
	 * The canonical ARN, rebuilt from the parsed fields rather than echoed from the
	 * input — this is what is persisted and what every KMS request names, so it
	 * cannot carry anything the validation above did not look at.
	 */
	public String keyArn() {
		return "arn:" + anchor.partition() + ":kms:" + anchor.region() + ":" + anchor.accountId() + ":"
				+ KEY_RESOURCE_PREFIX + keyId;
	}

	public String keyId() {
		return keyId;
	}
}
