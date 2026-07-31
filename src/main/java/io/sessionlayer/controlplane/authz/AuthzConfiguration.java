package io.sessionlayer.controlplane.authz;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Configuration(proxyBeanMethods = false)
@EnableConfigurationProperties({AuthzProperties.class, LockFeedProperties.class, SessionLimitProperties.class})
public class AuthzConfiguration {
}
