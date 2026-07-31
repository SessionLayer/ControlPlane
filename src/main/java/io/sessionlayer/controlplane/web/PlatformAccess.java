package io.sessionlayer.controlplane.web;

import io.sessionlayer.controlplane.platform.PlatformAuthorization;
import io.sessionlayer.controlplane.platform.PlatformSubject;
import io.sessionlayer.controlplane.security.CurrentAuthentication;
import java.util.function.Function;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

/**
 * Platform-RBAC gate for management controllers (no existence/permission
 * disclosure).
 */
@Component
public class PlatformAccess {

	private final PlatformAuthorization platformAuthorization;
	private final CurrentAuthentication currentAuthentication;

	public PlatformAccess(PlatformAuthorization platformAuthorization, CurrentAuthentication currentAuthentication) {
		this.platformAuthorization = platformAuthorization;
		this.currentAuthentication = currentAuthentication;
	}

	/**
	 * Whether an already-authorized subject also holds a second permission, for a
	 * projection that widens rather than a route that opens. Deliberately returns a
	 * boolean instead of a 403: the caller is allowed to be here, and the question
	 * is only how much of the resource it may see.
	 */
	public Mono<Boolean> holds(PlatformSubject subject, String permission) {
		return platformAuthorization.authorize(subject, permission, null).map(decision -> decision.allowed());
	}

	public <T> Mono<ResponseEntity<T>> withPermission(String permission,
			Function<PlatformSubject, Mono<ResponseEntity<T>>> action) {
		return currentAuthentication.subject()
				.flatMap(subject -> platformAuthorization.authorize(subject, permission, null)
						.flatMap(decision -> decision.allowed()
								? action.apply(subject)
								: Mono.just(ResponseEntity.status(HttpStatus.FORBIDDEN).<T>build())))
				.switchIfEmpty(Mono.just(ResponseEntity.status(HttpStatus.FORBIDDEN).build()));
	}
}
