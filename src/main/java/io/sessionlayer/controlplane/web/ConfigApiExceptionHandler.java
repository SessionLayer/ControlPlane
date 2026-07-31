package io.sessionlayer.controlplane.web;

import java.net.URI;
import org.springframework.http.MediaType;
import org.springframework.http.ProblemDetail;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

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
}
