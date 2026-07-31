package io.sessionlayer.controlplane.web;

import java.time.Duration;
import java.util.concurrent.TimeoutException;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

/**
 * Bounds every REST request to {@code sessionlayer.web.request-timeout}.
 * Ordered first so the deadline covers the whole downstream chain (security,
 * dispatch, handler) the same way the gRPC plane's per-RPC timeout does. A
 * request that times out before committing a response gets a clean 504 instead
 * of hanging the caller forever with no signal.
 */
@Component
@Order(Ordered.HIGHEST_PRECEDENCE)
class RequestDeadlineFilter implements WebFilter {

	private final Duration timeout;

	RequestDeadlineFilter(RequestDeadlineProperties properties) {
		this.timeout = properties.getRequestTimeout();
	}

	@Override
	public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
		return chain.filter(exchange).timeout(timeout).onErrorResume(TimeoutException.class, e -> {
			if (exchange.getResponse().isCommitted()) {
				return Mono.empty();
			}
			exchange.getResponse().setStatusCode(HttpStatus.GATEWAY_TIMEOUT);
			return exchange.getResponse().setComplete();
		});
	}
}
