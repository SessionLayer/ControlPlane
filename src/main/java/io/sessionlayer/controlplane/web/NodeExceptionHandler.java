package io.sessionlayer.controlplane.web;

import io.sessionlayer.controlplane.node.NodeRequestException;
import java.net.URI;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ProblemDetail;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@RestControllerAdvice(assignableTypes = NodeController.class)
class NodeExceptionHandler {

	@ExceptionHandler(NodeRequestException.class)
	ResponseEntity<ProblemDetail> onNodeRequest(NodeRequestException failure) {
		HttpStatus status = switch (failure.reason()) {
			case INVALID_ARGUMENT -> HttpStatus.BAD_REQUEST;
			case NOT_FOUND -> HttpStatus.NOT_FOUND;
			case CONFLICT -> HttpStatus.CONFLICT;
			// UNPROCESSABLE_CONTENT, not the deprecated UNPROCESSABLE_ENTITY alias: both
			// are 422, but they are distinct enum constants and HttpStatusCode.valueOf(422)
			// resolves to this one — anything comparing status objects rather than codes
			// reads the alias as a different status.
			case UNPROCESSABLE -> HttpStatus.UNPROCESSABLE_CONTENT;
		};
		ProblemDetail problem = ProblemDetail.forStatusAndDetail(status, failure.getMessage());
		// The title stays as published — the vocabulary is shared, the wording is this
		// controller's, and changing a response body the contract did not change would
		// be a breaking change for a cosmetic gain.
		problem.setType(URI.create(problemType(failure.reason()).typeUri()));
		problem.setTitle("Node request rejected");
		return ResponseEntity.status(status).contentType(MediaType.APPLICATION_PROBLEM_JSON).body(problem);
	}

	private static ApiProblemType problemType(NodeRequestException.Reason reason) {
		return switch (reason) {
			case INVALID_ARGUMENT -> ApiProblemType.MALFORMED;
			case NOT_FOUND -> ApiProblemType.NOT_FOUND;
			case CONFLICT -> ApiProblemType.CONFLICT;
			case UNPROCESSABLE -> ApiProblemType.VALIDATION;
		};
	}
}
