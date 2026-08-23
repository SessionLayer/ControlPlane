package io.sessionlayer.controlplane.ca.backend.aws;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.SocketTimeoutException;
import org.junit.jupiter.api.Test;
import software.amazon.awssdk.auth.credentials.DefaultCredentialsProvider;
import software.amazon.awssdk.http.apache5.Apache5HttpClient;

class AwsKmsCredentialsSmokeTest {

	@Test
	void theDefaultCredentialChainAndTheApache5TransportBothBuild() {
		assertThatCode(() -> {
			// Built and closed without resolving a credential: the chain does no I/O
			// until a request needs one, which is what keeps bean construction off the
			// network. Resolving here would make this test require an AWS environment.
			try (DefaultCredentialsProvider credentials = DefaultCredentialsProvider.builder().build()) {
				assertThat(credentials).isNotNull();
				Apache5HttpClient.builder().build().close();
			}
		}).doesNotThrowAnyException();
	}

	/**
	 * The async Netty transport is excluded because it is compiled against Netty
	 * 4.1 while this service runs 4.2. Excluding it is only worth anything if it
	 * stays excluded, and no compile error would ever report its return: it is a
	 * runtime-scoped transitive that becomes the default the moment an async client
	 * is built.
	 */
	@Test
	void theAsyncNettyTransportIsNotOnTheClasspath() {
		assertThatThrownBy(() -> Class.forName("software.amazon.awssdk.http.nio.netty.NettyNioAsyncHttpClient"))
				.isInstanceOf(ClassNotFoundException.class);
	}

	/**
	 * An eager call here would make bean creation depend on KMS being reachable at
	 * startup, which turns a key-service outage into a Control Plane that will not
	 * boot rather than one CA that cannot sign.
	 */
	@Test
	void constructingTheFactoryConnectsToNothing() throws Exception {
		try (ServerSocket endpoint = new ServerSocket(0, 1, InetAddress.getLoopbackAddress())) {
			AwsKmsProperties properties = new AwsKmsProperties();
			properties.setEnabled(true);
			properties.setRegion("us-east-1");
			properties.setAccountId("111122223333");
			properties.setAllowEndpointOverride(true);
			properties.setAllowInsecureEndpoint(true);
			properties.setEndpointOverride(
					"http://" + urlHost(InetAddress.getLoopbackAddress()) + ":" + endpoint.getLocalPort());

			new AwsKmsSignerFactory(properties).close();

			endpoint.setSoTimeout(250);
			assertThatThrownBy(endpoint::accept).isInstanceOf(SocketTimeoutException.class);
		}
	}

	private static String urlHost(InetAddress address) {
		String literal = address.getHostAddress();
		return literal.contains(":") ? "[" + literal + "]" : literal;
	}
}
