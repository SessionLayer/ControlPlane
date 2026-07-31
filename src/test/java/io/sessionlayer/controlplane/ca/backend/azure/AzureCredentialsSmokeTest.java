package io.sessionlayer.controlplane.ca.backend.azure;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;

import com.azure.core.http.HttpClient;
import com.azure.core.http.jdk.httpclient.JdkHttpClientProvider;
import com.azure.identity.DefaultAzureCredentialBuilder;
import org.junit.jupiter.api.Test;

/**
 * The Azure dependency tree is trimmed by four exclusions in {@code pom.xml};
 * this is the evidence that none of them removed a class a live path reaches.
 * {@code msal4j-persistence-extension} and JNA are excluded on the argument
 * that only the persistent token cache uses them, and
 * {@code azure-core-http-netty} on the argument that the JDK provider replaces
 * it — arguments about code that is not executed until a credential is first
 * used, which is when a {@code NoClassDefFoundError} would otherwise surface,
 * in production, mid-signature.
 */
class AzureCredentialsSmokeTest {

	@Test
	void defaultCredentialChainBuildsWithoutThePersistenceExtension() {
		assertThatCode(() -> new DefaultAzureCredentialBuilder().build()).doesNotThrowAnyException();
	}

	/**
	 * The HTTP client is selected explicitly in production rather than left to SPI
	 * discovery, but the discovered default must still be the JDK one: a transitive
	 * dependency re-introducing the Netty provider would otherwise change the
	 * transport of every unconfigured Azure client silently.
	 */
	@Test
	void theOnlyHttpClientProviderIsTheJdkOne() {
		assertThat(HttpClient.createDefault()).isInstanceOf(new JdkHttpClientProvider().createInstance().getClass());
	}
}
