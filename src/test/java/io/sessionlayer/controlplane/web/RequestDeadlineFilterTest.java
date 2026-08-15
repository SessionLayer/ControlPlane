package io.sessionlayer.controlplane.web;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Duration;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

// Without this filter a wedged downstream (lock contention, a stalled
// scan) hangs the caller's connection forever with no signal at all.
class RequestDeadlineFilterTest {

	private ServerWebExchange exchange() {
		return MockServerWebExchange.from(MockServerHttpRequest.get("/v1/audit-events").build());
	}

	@Test
	void aWedgedDownstreamGetsAClean504InsteadOfHangingForever() {
		RequestDeadlineProperties properties = new RequestDeadlineProperties();
		properties.setRequestTimeout(Duration.ofMillis(100));
		RequestDeadlineFilter filter = new RequestDeadlineFilter(properties);
		ServerWebExchange exchange = exchange();

		filter.filter(exchange, ex -> Mono.never()).block(Duration.ofSeconds(2));

		assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.GATEWAY_TIMEOUT);
	}

	@Test
	void aRequestThatCompletesWellWithinTheDeadlineIsUntouched() {
		RequestDeadlineProperties properties = new RequestDeadlineProperties();
		properties.setRequestTimeout(Duration.ofSeconds(5));
		RequestDeadlineFilter filter = new RequestDeadlineFilter(properties);
		ServerWebExchange exchange = exchange();

		filter.filter(exchange, ex -> Mono.empty()).block(Duration.ofSeconds(2));

		assertThat(exchange.getResponse().getStatusCode()).isNotEqualTo(HttpStatus.GATEWAY_TIMEOUT);
	}
}
