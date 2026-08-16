package io.sessionlayer.controlplane.oidc;

import java.util.List;

public record ResolvedIdentity(String identity, List<String> groups, String subject) {
}
