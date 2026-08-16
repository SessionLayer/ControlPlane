package io.sessionlayer.controlplane.web;

import org.springframework.http.HttpStatusCode;

public enum ApiProblemType {

	VALIDATION("validation-error", 422, "Invalid configuration"), MALFORMED("malformed-request", 400,
			"Malformed request"), NOT_FOUND("not-found", 404, "Resource not found"), CONFLICT("conflict", 409,
					"Conflict"), IDEMPOTENCY_CONFLICT("idempotency-key-conflict", 422,
							"Idempotency-Key reuse conflict");

	private static final String BASE = "https://docs.sessionlayer.example/problems/";

	private final String slug;
	private final int statusCode;
	private final String title;

	ApiProblemType(String slug, int statusCode, String title) {
		this.slug = slug;
		this.statusCode = statusCode;
		this.title = title;
	}

	public String typeUri() {
		return BASE + slug;
	}

	public HttpStatusCode status() {
		return HttpStatusCode.valueOf(statusCode);
	}

	public String title() {
		return title;
	}
}
