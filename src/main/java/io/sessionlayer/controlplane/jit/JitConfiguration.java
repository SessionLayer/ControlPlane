package io.sessionlayer.controlplane.jit;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Configuration(proxyBeanMethods = false)
@EnableConfigurationProperties(JitProperties.class)
public class JitConfiguration {
}
