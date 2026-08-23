package io.sessionlayer.controlplane.web;

import io.sessionlayer.controlplane.jit.JitException;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ProblemDetail;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@RestControllerAdvice(assignableTypes = JitRequestController.class)
class JitExceptionHandler {

	@ExceptionHandler(JitException.class)
	ResponseEntity<ProblemDetail> onJitError(JitException failure) {
		HttpStatus status = switch (failure.reason()) {
			case NOT_FOUND -> HttpStatus.NOT_FOUND;
			case INVALID, NOT_REQUESTABLE -> HttpStatus.BAD_REQUEST;
			case SELF_APPROVAL, NOT_AN_APPROVER -> HttpStatus.FORBIDDEN;
			case NOT_PENDING, ALREADY_ACTED, NOT_REVOCABLE -> HttpStatus.CONFLICT;
		};
		ProblemDetail problem = ProblemDetail.forStatusAndDetail(status, failure.getMessage());
		problem.setTitle("JIT request error");
		return ResponseEntity.status(status).contentType(MediaType.APPLICATION_PROBLEM_JSON).body(problem);
	}
}
