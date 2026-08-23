package io.sessionlayer.controlplane.oidc;

import java.time.Duration;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.reactive.function.BodyInserters;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;
import tools.jackson.databind.JsonNode;

@Service
public class OidcClient {

	private final WebClient http;
	private final OidcProperties properties;

	public OidcClient(WebClient.Builder httpBuilder, OidcProperties properties) {
		this.http = httpBuilder.build();
		this.properties = properties;
	}

	public Mono<String> exchangeCode(OidcDiscovery discovery, String code, String codeVerifier) {
		MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
		form.add("grant_type", "authorization_code");
		form.add("code", code);
		form.add("redirect_uri", properties.getRedirectUri());
		form.add("client_id", properties.getClientId());
		form.add("code_verifier", codeVerifier);
		if (properties.getClientSecret() != null && !properties.getClientSecret().isBlank()) {
			form.add("client_secret", properties.getClientSecret());
		}
		return http.post().uri(discovery.tokenEndpoint()).contentType(MediaType.APPLICATION_FORM_URLENCODED)
				.body(BodyInserters.fromFormData(form)).retrieve().bodyToMono(JsonNode.class)
				.timeout(Duration.ofSeconds(15)).map(body -> {
					JsonNode idToken = body.get("id_token");
					if (idToken == null || idToken.isNull()) {
						throw new IllegalStateException("token response has no id_token");
					}
					return idToken.asString();
				});
	}
}
