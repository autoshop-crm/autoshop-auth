package com.vladko.autoshopauth.integration.core.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "app.core")
public record CoreSyncProperties(String baseUrl, String syncToken) {
}
