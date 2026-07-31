package io.sessionlayer.controlplane.oidc;

import java.util.List;

/**
 * Server-side-resolved identity + groups from IdP claims (never client-chosen).
 */
public record ResolvedIdentity(String identity, List<String> groups, String subject) {
}
