package io.sessionlayer.controlplane.web;

import io.sessionlayer.controlplane.bootstrap.BootstrapService;
import io.sessionlayer.controlplane.bootstrap.BootstrapService.ClaimOutcome;
import java.util.Map;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;

@RestController
public class BootstrapController {

	private final BootstrapService bootstrapService;

	public BootstrapController(BootstrapService bootstrapService) {
		this.bootstrapService = bootstrapService;
	}

	public record ClaimRequest(String credential, String subject) {
	}

	@PostMapping("/v1/bootstrap/claim")
	public Mono<ResponseEntity<Map<String, String>>> claim(@RequestBody ClaimRequest request) {
		return bootstrapService.claim(request.credential(), request.subject()).map(BootstrapController::toResponse);
	}

	private static ResponseEntity<Map<String, String>> toResponse(ClaimOutcome outcome) {
		return switch (outcome) {
			case PROVISIONED -> ResponseEntity.ok(Map.of("status", "provisioned"));
			case ALREADY_COMPLETED ->
				ResponseEntity.status(HttpStatus.CONFLICT).body(Map.of("status", "already_completed"));
			case NOT_CREDENTIAL_MODE ->
				ResponseEntity.status(HttpStatus.CONFLICT).body(Map.of("status", "not_available"));
			case INVALID_CREDENTIAL ->
				ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of("status", "invalid_credential"));
		};
	}
}
