package io.sessionlayer.controlplane.audit;

import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.annotation.EnableScheduling;

/**
 * Enables scheduling for audit-partition create-ahead maintenance.
 */
@Configuration(proxyBeanMethods = false)
@EnableScheduling
public class AuditConfiguration {
}
