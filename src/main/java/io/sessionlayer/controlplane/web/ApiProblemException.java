package io.sessionlayer.controlplane.web;

import java.util.UUID;

/**
 * Carries no secret/entity material — only short human-readable detail.
 */
public class ApiProblemException extends RuntimeException {

	private final transient ApiProblemType type;

	public ApiProblemException(ApiProblemType type, String detail) {
		super(detail);
		this.type = type;
	}

	public ApiProblemType type() {
		return type;
	}

	public static ApiProblemException validation(String detail) {
		return new ApiProblemException(ApiProblemType.VALIDATION, detail);
	}

	public static ApiProblemException malformed(String detail) {
		return new ApiProblemException(ApiProblemType.MALFORMED, detail);
	}

	public static ApiProblemException notFound(String kind, UUID id) {
		return new ApiProblemException(ApiProblemType.NOT_FOUND, kind + " " + id + " not found");
	}

	public static ApiProblemException conflict(String detail) {
		return new ApiProblemException(ApiProblemType.CONFLICT, detail);
	}

	public static ApiProblemException idempotencyConflict() {
		return new ApiProblemException(ApiProblemType.IDEMPOTENCY_CONFLICT,
				"the Idempotency-Key was reused with a different request");
	}
}
