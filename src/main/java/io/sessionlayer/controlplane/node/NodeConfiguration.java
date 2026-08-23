package io.sessionlayer.controlplane.node;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Configuration(proxyBeanMethods = false)
@EnableConfigurationProperties(NodeLifecycleProperties.class)
public class NodeConfiguration {
}
