package io.sessionlayer.controlplane.agent;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Configuration(proxyBeanMethods = false)
@EnableConfigurationProperties(AgentJoinProperties.class)
public class AgentJoinConfiguration {
}
