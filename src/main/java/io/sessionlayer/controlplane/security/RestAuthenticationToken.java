package io.sessionlayer.controlplane.security;

import java.util.Collection;
import java.util.List;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

public final class RestAuthenticationToken extends AbstractAuthenticationToken {

	private final AuthenticatedPrincipal principal;

	public RestAuthenticationToken(AuthenticatedPrincipal principal) {
		super(authorities(principal.groups()));
		this.principal = principal;
		setAuthenticated(true);
	}

	private static Collection<GrantedAuthority> authorities(List<String> groups) {
		return groups.stream().map(g -> (GrantedAuthority) new SimpleGrantedAuthority("GROUP_" + g)).toList();
	}

	@Override
	public AuthenticatedPrincipal getPrincipal() {
		return principal;
	}

	@Override
	public Object getCredentials() {
		return "";
	}

	@Override
	public String getName() {
		return principal.identity();
	}
}
