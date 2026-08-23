package io.sessionlayer.controlplane.web;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Configuration(proxyBeanMethods = false)
@EnableConfigurationProperties(RequestDeadlineProperties.class)
class RequestDeadlineConfiguration {
}
