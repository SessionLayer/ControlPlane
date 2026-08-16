package io.sessionlayer.controlplane.observability;

import io.opentelemetry.exporter.otlp.http.trace.OtlpHttpSpanExporter;
import io.opentelemetry.sdk.trace.export.SpanExporter;
import java.util.Optional;

final class OtlpTraceExporter {

	private static final String TRACES_PATH = "/v1/traces";

	private OtlpTraceExporter() {
	}

	static Optional<SpanExporter> forEndpoint(String endpoint) {
		if (endpoint == null || endpoint.isBlank()) {
			return Optional.empty();
		}
		// OTEL_EXPORTER_OTLP_ENDPOINT is the collector BASE; OTLP/HTTP traces post to
		// /v1/traces. Append it when the operator gave a bare base (the common case).
		String base = endpoint.strip();
		String url = base.endsWith(TRACES_PATH) ? base : base.replaceAll("/+$", "") + TRACES_PATH;
		return Optional.of(OtlpHttpSpanExporter.builder().setEndpoint(url).build());
	}
}
