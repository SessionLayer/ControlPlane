package io.sessionlayer.controlplane.ca.backend.azure;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;

/**
 * A misconfigured {@code sessionlayer.ca.azure.*} fails the application context
 * at startup, naming the property — never a listener that reaches the database
 * or network, which is how a blocking readiness check crash-loops a whole fleet
 * instead of refusing one bad config value.
 */
class AzureKeyVaultPropertiesTest {

	private final ApplicationContextRunner contextRunner = new ApplicationContextRunner()
			.withUserConfiguration(AzureKeyVaultConfiguration.class);

	@Test
	void disabledNeedsNoVaultUri() {
		AzureKeyVaultProperties properties = new AzureKeyVaultProperties();
		assertThatCode(properties::validate).doesNotThrowAnyException();
	}

	@Test
	void enabledWithAWellFormedHttpsVaultUriStarts() {
		AzureKeyVaultProperties properties = new AzureKeyVaultProperties();
		properties.setEnabled(true);
		properties.setVaultUri("https://myvault.vault.azure.net");
		assertThatCode(properties::validate).doesNotThrowAnyException();
	}

	@Test
	void enabledWithNoVaultUriRefusesToStart() {
		AzureKeyVaultProperties properties = new AzureKeyVaultProperties();
		properties.setEnabled(true);
		assertThatThrownBy(properties::validate).isInstanceOf(IllegalStateException.class)
				.hasMessageContaining("sessionlayer.ca.azure.vault-uri");
	}

	@Test
	void enabledWithABlankVaultUriRefusesToStart() {
		AzureKeyVaultProperties properties = new AzureKeyVaultProperties();
		properties.setEnabled(true);
		properties.setVaultUri("   ");
		assertThatThrownBy(properties::validate).isInstanceOf(IllegalStateException.class)
				.hasMessageContaining("sessionlayer.ca.azure.vault-uri");
	}

	@Test
	void enabledWithAnHttpVaultUriRefusesToStart() {
		AzureKeyVaultProperties properties = new AzureKeyVaultProperties();
		properties.setEnabled(true);
		properties.setVaultUri("http://myvault.vault.azure.net");
		assertThatThrownBy(properties::validate).isInstanceOf(IllegalStateException.class)
				.hasMessageContaining("https");
	}

	@Test
	void enabledWithAnUnparseableVaultUriRefusesToStart() {
		AzureKeyVaultProperties properties = new AzureKeyVaultProperties();
		properties.setEnabled(true);
		properties.setVaultUri("not a valid uri");
		assertThatThrownBy(properties::validate).isInstanceOf(IllegalStateException.class)
				.hasMessageContaining("sessionlayer.ca.azure.vault-uri");
	}

	@Test
	void theApplicationContextItselfFailsToStartWithNoVaultUri() {
		contextRunner.withPropertyValues("sessionlayer.ca.azure.enabled=true")
				.run(context -> assertThat(context).hasFailed().getFailure().rootCause()
						.isInstanceOf(IllegalStateException.class)
						.hasMessageContaining("sessionlayer.ca.azure.vault-uri"));
	}

	@Test
	void theApplicationContextItselfFailsToStartWithAnHttpVaultUri() {
		contextRunner
				.withPropertyValues("sessionlayer.ca.azure.enabled=true",
						"sessionlayer.ca.azure.vault-uri=http://myvault.vault.azure.net")
				.run(context -> assertThat(context).hasFailed().getFailure().rootCause()
						.isInstanceOf(IllegalStateException.class).hasMessageContaining("https"));
	}

	@Test
	void theApplicationContextStartsCleanWhenDisabled() {
		contextRunner.run(context -> assertThat(context).hasNotFailed());
	}
}
