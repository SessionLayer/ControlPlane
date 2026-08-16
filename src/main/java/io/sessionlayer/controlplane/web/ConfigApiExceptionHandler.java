package io.sessionlayer.controlplane.web;

import java.net.URI;
import java.util.List;
import org.springframework.http.MediaType;
import org.springframework.http.ProblemDetail;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.bind.support.WebExchangeBindException;
import org.springframework.web.server.ServerWebInputException;

@RestControllerAdvice
class ConfigApiExceptionHandler {

	@ExceptionHandler(ApiProblemException.class)
	ResponseEntity<ProblemDetail> onApiProblem(ApiProblemException failure) {
		ApiProblemType type = failure.type();
		ProblemDetail problem = ProblemDetail.forStatusAndDetail(type.status(), failure.getMessage());
		problem.setType(URI.create(type.typeUri()));
		problem.setTitle(type.title());
		return ResponseEntity.status(type.status()).contentType(MediaType.APPLICATION_PROBLEM_JSON).body(problem);
	}

	/**
	 * The status Spring chose is preserved rather than reassigned. The defect is
	 * the missing field name, not the number, and re-mapping these to {@code 422}
	 * would silently change the answer of every operation on the surface at once.
	 */
	@ExceptionHandler(WebExchangeBindException.class)
	ResponseEntity<ProblemDetail> onBindFailure(WebExchangeBindException failure) {
		List<FieldError> fieldErrors = failure.getFieldErrors();
		String detail = fieldErrors.isEmpty()
				? reasonOf(failure)
				: fieldErrors.stream().map(ConfigApiExceptionHandler::describe).reduce((a, b) -> a + "; " + b)
						.orElse("");
		return problem(failure.getStatusCode().value(), detail);
	}

	@ExceptionHandler(ServerWebInputException.class)
	ResponseEntity<ProblemDetail> onInputFailure(ServerWebInputException failure) {
		return problem(failure.getStatusCode().value(), reasonOf(failure));
	}

	private static ResponseEntity<ProblemDetail> problem(int status, String detail) {
		ApiProblemType type = status == ApiProblemType.VALIDATION.status().value()
				? ApiProblemType.VALIDATION
				: ApiProblemType.MALFORMED;
		ProblemDetail problem = ProblemDetail.forStatusAndDetail(type.status(), detail);
		problem.setType(URI.create(type.typeUri()));
		problem.setTitle(type.title());
		return ResponseEntity.status(status).contentType(MediaType.APPLICATION_PROBLEM_JSON).body(problem);
	}

	private static String describe(FieldError error) {
		return error.getField() + ": " + (error.getDefaultMessage() == null ? "is invalid" : error.getDefaultMessage());
	}

	// Never echo the exception's toString: it carries the resolved handler method
	// and argument types, which are internals rather than an operator's answer.
	private static String reasonOf(ServerWebInputException failure) {
		String reason = failure.getReason();
		return reason == null || reason.isBlank() ? "the request could not be read" : reason;
	}
}
