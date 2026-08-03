package io.sessionlayer.controlplane.ca.backend.aws;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.sessionlayer.controlplane.ca.backend.aws.KmsKeyArn.Anchor;
import io.sessionlayer.controlplane.ca.backend.aws.KmsKeyArn.InvalidKeyReference;
import org.junit.jupiter.api.Test;

/**
 * {@link KmsKeyArn} is a pure security boundary — every rejection is exercised
 * in isolation so a regression names the exact clause it broke.
 */
class KmsKeyArnTest {

	private static final Anchor ANCHOR = new Anchor("aws", "us-east-1", "111122223333");

	private static final String KEY_ID = "1234abcd-12ab-34cd-56ef-1234567890ab";

	private static final String ARN = "arn:aws:kms:us-east-1:111122223333:key/" + KEY_ID;

	@Test
	void parsesAWellFormedKeyArn() {
		KmsKeyArn ref = KmsKeyArn.parse(ARN, ANCHOR);

		assertThat(ref.keyId()).isEqualTo(KEY_ID);
		assertThat(ref.keyArn()).isEqualTo(ARN);
	}

	/**
	 * A multi-Region key is an ordinary pinned key from this seam's point of view:
	 * its id is stable and its material never changes, so the only difference is
	 * the id's shape.
	 */
	@Test
	void parsesAMultiRegionKeyId() {
		String mrk = "mrk-" + "0123456789abcdef0123456789abcdef";
		KmsKeyArn ref = KmsKeyArn.parse("arn:aws:kms:us-east-1:111122223333:key/" + mrk, ANCHOR);

		assertThat(ref.keyId()).isEqualTo(mrk);
	}

	@Test
	void parsesAKeyInANonDefaultPartition() {
		Anchor govCloud = new Anchor("aws-us-gov", "us-gov-west-1", "111122223333");
		KmsKeyArn ref = KmsKeyArn.parse("arn:aws-us-gov:kms:us-gov-west-1:111122223333:key/" + KEY_ID, govCloud);

		assertThat(ref.keyArn()).isEqualTo("arn:aws-us-gov:kms:us-gov-west-1:111122223333:key/" + KEY_ID);
	}

	/**
	 * The alias refusal is the pinning guarantee. {@code kms:UpdateAlias} repoints
	 * an alias at a different key with nothing visible changing here, so a CA on an
	 * alias would silently start signing with a key whose public half is in no
	 * node's trusted set.
	 */
	@Test
	void rejectsAnAliasArn() {
		assertThatThrownBy(() -> KmsKeyArn.parse("arn:aws:kms:us-east-1:111122223333:alias/session-ca", ANCHOR))
				.isInstanceOf(InvalidKeyReference.class).hasMessageContaining("is a KMS alias")
				.hasMessageContaining("Use the key ARN");
	}

	@Test
	void rejectsABareAlias() {
		assertThatThrownBy(() -> KmsKeyArn.parse("alias/session-ca", ANCHOR)).isInstanceOf(InvalidKeyReference.class)
				.hasMessageContaining("is a KMS alias");
	}

	/**
	 * A bare key id carries no account, region or partition, so the allow-list
	 * anchor has nothing to compare and the reference would resolve against
	 * whatever the process is pointed at.
	 */
	@Test
	void rejectsABareKeyId() {
		assertThatThrownBy(() -> KmsKeyArn.parse(KEY_ID, ANCHOR)).isInstanceOf(InvalidKeyReference.class)
				.hasMessageContaining("is not a KMS key ARN");
	}

	@Test
	void rejectsAnArnInAnotherRegion() {
		assertThatThrownBy(() -> KmsKeyArn.parse("arn:aws:kms:eu-west-1:111122223333:key/" + KEY_ID, ANCHOR))
				.isInstanceOf(InvalidKeyReference.class).hasMessageContaining("names region 'eu-west-1'")
				.hasMessageContaining("only the configured account, region and partition are permitted");
	}

	/** The anchor a compromised {@code ca_config} row cannot reach. */
	@Test
	void rejectsAnArnInAnotherAccount() {
		assertThatThrownBy(() -> KmsKeyArn.parse("arn:aws:kms:us-east-1:999988887777:key/" + KEY_ID, ANCHOR))
				.isInstanceOf(InvalidKeyReference.class).hasMessageContaining("names account-id '999988887777'");
	}

	@Test
	void rejectsAnArnInAnotherPartition() {
		assertThatThrownBy(() -> KmsKeyArn.parse("arn:aws-cn:kms:us-east-1:111122223333:key/" + KEY_ID, ANCHOR))
				.isInstanceOf(InvalidKeyReference.class).hasMessageContaining("names partition 'aws-cn'");
	}

	/**
	 * An ARN whose account, region and partition all match the anchor but which
	 * names a different service: the anchor alone would pass it, so the service
	 * field is checked in its own right.
	 */
	@Test
	void rejectsAnArnForAnotherService() {
		assertThatThrownBy(() -> KmsKeyArn.parse("arn:aws:s3:us-east-1:111122223333:key/" + KEY_ID, ANCHOR))
				.isInstanceOf(InvalidKeyReference.class).hasMessageContaining("names the 's3' service, not 'kms'");
	}

	@Test
	void rejectsAResourceThatIsNotAKey() {
		assertThatThrownBy(() -> KmsKeyArn.parse("arn:aws:kms:us-east-1:111122223333:replica-key/" + KEY_ID, ANCHOR))
				.isInstanceOf(InvalidKeyReference.class).hasMessageContaining("not of the form key/{key-id}");
	}

	/**
	 * A URL-authority shape is what has fooled naive prefix checks elsewhere: the
	 * part before {@code @} looks like the real value to a careless reader. Both
	 * halves are pinned — junk ahead of the ARN and junk appended to the key id.
	 */
	@Test
	void rejectsUserinfoStyleJunkAroundTheArn() {
		assertThatThrownBy(() -> KmsKeyArn.parse("evil@" + ARN, ANCHOR)).isInstanceOf(InvalidKeyReference.class)
				.hasMessageContaining("is not a KMS key ARN");
		assertThatThrownBy(() -> KmsKeyArn.parse(ARN + "@attacker.example.com", ANCHOR))
				.isInstanceOf(InvalidKeyReference.class).hasMessageContaining("invalid key id");
	}

	@Test
	void rejectsAnArnWithExtraColonSeparatedSegments() {
		assertThatThrownBy(() -> KmsKeyArn.parse(ARN + ":extra", ANCHOR)).isInstanceOf(InvalidKeyReference.class)
				.hasMessageContaining("is not a KMS key ARN");
	}

	@Test
	void rejectsAnArnWithTooFewSegments() {
		assertThatThrownBy(() -> KmsKeyArn.parse("arn:aws:kms:us-east-1:key/" + KEY_ID, ANCHOR))
				.isInstanceOf(InvalidKeyReference.class).hasMessageContaining("is not a KMS key ARN");
	}

	/**
	 * The key id is allow-listed to the two shapes KMS issues, not merely required
	 * to be present: a value that occupies the position without being a key id is
	 * refused the same as one that is absent.
	 */
	@Test
	void rejectsAKeyIdThatIsNotAUuidOrMultiRegionId() {
		for (String bad : new String[]{"", "session-ca", "1234ABCD-12ab-34cd-56ef-1234567890ab",
				"1234abcd-12ab-34cd-56ef-1234567890a", "mrk-0123456789abcdef", KEY_ID + "/extra"}) {
			assertThatThrownBy(() -> KmsKeyArn.parse("arn:aws:kms:us-east-1:111122223333:key/" + bad, ANCHOR)).as(bad)
					.isInstanceOf(InvalidKeyReference.class).hasMessageContaining("invalid key id");
		}
	}

	/**
	 * A control character surviving into {@code ca_config.key_reference} would be
	 * persisted and later rendered in audit diffs; the same allow-list that refuses
	 * a name refuses this, for the same reason.
	 */
	@Test
	void rejectsAControlCharacterInTheKeyId() {
		assertThatThrownBy(
				() -> KmsKeyArn.parse("arn:aws:kms:us-east-1:111122223333:key/" + KEY_ID + "\r\nX-Injected", ANCHOR))
				.isInstanceOf(InvalidKeyReference.class).hasMessageContaining("invalid key id");
	}

	@Test
	void rejectsABlankReference() {
		assertThatThrownBy(() -> KmsKeyArn.parse("", ANCHOR)).isInstanceOf(InvalidKeyReference.class);
		assertThatThrownBy(() -> KmsKeyArn.parse(null, ANCHOR)).isInstanceOf(InvalidKeyReference.class);
	}

	/**
	 * A misconfigured anchor is a configuration bug, not a bad key_reference:
	 * {@code AwsKmsProperties} already refuses to start this way, so reaching here
	 * means that guard was bypassed and the failure must say so.
	 */
	@Test
	void aMisconfiguredAnchorFailsClosedAsAConfigurationBug() {
		assertThatThrownBy(() -> new Anchor("aws", "us-east-1", "not-an-account"))
				.isInstanceOf(IllegalStateException.class).hasMessageContaining("sessionlayer.ca.aws.account-id");
		assertThatThrownBy(() -> new Anchor("aws", null, "111122223333")).isInstanceOf(IllegalStateException.class)
				.hasMessageContaining("sessionlayer.ca.aws.region");
		assertThatThrownBy(() -> new Anchor("azure", "us-east-1", "111122223333"))
				.isInstanceOf(IllegalStateException.class).hasMessageContaining("sessionlayer.ca.aws.partition");
	}

	/**
	 * Everything human- or telemetry-facing renders this form, so the account id
	 * must not survive it while the key stays identifiable.
	 */
	@Test
	void redactsTheAccountIdButStillNamesTheKey() {
		String redacted = KmsKeyArn.parse(ARN, ANCHOR).redacted();

		assertThat(redacted).doesNotContain("111122223333").contains(KEY_ID).contains("us-east-1")
				.isEqualTo("arn:aws:kms:us-east-1:***:key/" + KEY_ID);
	}

	/**
	 * The anchor mismatch is the one refusal that could turn a {@code 422} into a
	 * read of this deployment's account id: the caller learns their own ARN was
	 * rejected, never which account would have been accepted.
	 */
	@Test
	void aWrongAccountIsRefusedWithoutNamingTheConfiguredOne() {
		String otherAccount = "arn:aws:kms:us-east-1:999988887777:key/" + KEY_ID;

		assertThatThrownBy(() -> KmsKeyArn.parse(otherAccount, ANCHOR)).isInstanceOf(InvalidKeyReference.class)
				.hasMessageContaining("999988887777").hasMessageNotContaining("111122223333");
	}
}
