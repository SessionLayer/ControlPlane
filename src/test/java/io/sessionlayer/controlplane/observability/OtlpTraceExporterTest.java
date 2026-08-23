package io.sessionlayer.controlplane.observability;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

class OtlpTraceExporterTest {

	@Test
	void blankEndpointYieldsNoExporter() {
		assertThat(OtlpTraceExporter.forEndpoint(null)).isEmpty();
		assertThat(OtlpTraceExporter.forEndpoint("")).isEmpty();
		assertThat(OtlpTraceExporter.forEndpoint("   ")).isEmpty();
	}

	@Test
	void configuredEndpointYieldsAnExporter() {
		assertThat(OtlpTraceExporter.forEndpoint("http://collector:4318")).isPresent();
		assertThat(OtlpTraceExporter.forEndpoint("http://collector:4318/v1/traces")).isPresent();
	}
}
