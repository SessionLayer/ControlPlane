package io.sessionlayer.controlplane.ca;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.sessionlayer.controlplane.ca.backend.local.InsecureKekException;
import io.sessionlayer.controlplane.ca.backend.local.KekFailureAnalyzer;
import io.sessionlayer.controlplane.ca.backend.local.KekProvider;
import java.io.IOException;
import java.util.Objects;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.BeanCreationException;
import org.springframework.boot.diagnostics.FailureAnalysis;
import org.springframework.boot.diagnostics.FailureAnalyzer;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.support.SpringFactoriesLoader;

/**
 * The refusal itself is covered by {@link KekTest}. This covers whether an
 * operator can read it: on a crash-looping pod the message arrives wrapped in
 * Spring's bean-creation chain, and only a registered analyzer puts it in the
 * APPLICATION FAILED TO START block at the end of the log.
 */
class KekFailureAnalysisTest {

	@Test
	void theRefusalIsItsOwnTypeSoAnAnalyzerCanMatchIt() {
		assertThatThrownBy(() -> new KekProvider(KekProvider.DEV_DEFAULT_KEK_BASE64, null, false))
				.isInstanceOf(InsecureKekException.class);
	}

	/**
	 * Boot instantiates the registered analyzers itself; some of its own need
	 * constructor arguments this loader cannot supply, so failures to build those
	 * are ignored and only ours has to appear.
	 */
	private static FailureAnalyzer loadOurs() {
		return SpringFactoriesLoader.forDefaultResourceLocation().load(FailureAnalyzer.class,
				SpringFactoriesLoader.ArgumentResolver.none(), (type, implementation, failure) -> {
				}).stream().filter(Objects::nonNull).filter(a -> a.getClass().getName().endsWith("KekFailureAnalyzer"))
				.findFirst().orElse(null);
	}

	@Test
	void springLoadsTheAnalyzer() throws IOException {
		String registrations = new ClassPathResource("META-INF/spring.factories").getContentAsString(UTF_8);
		assertThat(registrations).as("Spring finds analyzers only through this file")
				.contains("org.springframework.boot.diagnostics.FailureAnalyzer")
				.contains(KekFailureAnalyzer.class.getName());
		assertThat(loadOurs()).as("registered, and instantiable by Spring's own loader").isNotNull();
	}

	@Test
	void itExplainsTheFailureAndNamesTheVariableAnOperatorActuallySets() {
		FailureAnalyzer analyzer = loadOurs();

		// The shape the JVM hands the analyzer in production: the refusal
		// buried inside the bean-creation failure that actually stops the boot.
		Throwable rootFailure = new BeanCreationException("Error creating bean with name 'kekProvider'",
				new InsecureKekException("refusing to start: the local CA KEK is the built-in DEV default"));

		FailureAnalysis analysis = analyzer.analyze(rootFailure);
		assertThat(analysis).isNotNull();
		assertThat(analysis.getDescription()).contains("key-encryption key").contains("public constant");
		assertThat(analysis.getAction()).contains("SESSIONLAYER_CA_LOCAL_KEK_BASE64").contains("secrets.existingSecret")
				.contains("sessionlayer.ca.local.kek-base64").contains("SESSIONLAYER_CA_LOCAL_ALLOW_DEV_KEK");
		assertThat(analysis.getCause()).isInstanceOf(InsecureKekException.class);
	}
}
