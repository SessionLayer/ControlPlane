package io.sessionlayer.controlplane.oidc;

public record OidcDiscovery(String issuer, String authorizationEndpoint, String tokenEndpoint, String jwksUri,
		String deviceAuthorizationEndpoint, String endSessionEndpoint) {
}
