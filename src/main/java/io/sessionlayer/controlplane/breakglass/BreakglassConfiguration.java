package io.sessionlayer.controlplane.breakglass;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Configuration(proxyBeanMethods = false)
@EnableConfigurationProperties(BreakglassProperties.class)
public class BreakglassConfiguration {
}
