package io.sessionlayer.controlplane.web;

import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ProblemDetail;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@RestControllerAdvice(assignableTypes = LockController.class)
class LockExceptionHandler {

	@ExceptionHandler(LockValidationException.class)
	ResponseEntity<ProblemDetail> onInvalidLock(LockValidationException failure) {
		ProblemDetail problem = ProblemDetail.forStatusAndDetail(HttpStatus.BAD_REQUEST, failure.getMessage());
		problem.setTitle("Invalid lock");
		return ResponseEntity.badRequest().contentType(MediaType.APPLICATION_PROBLEM_JSON).body(problem);
	}
}
