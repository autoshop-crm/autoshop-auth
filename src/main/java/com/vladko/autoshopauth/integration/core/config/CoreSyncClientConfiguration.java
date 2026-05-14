package com.vladko.autoshopauth.integration.core.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.client.RestClient;

@Configuration
public class CoreSyncClientConfiguration {

    @Bean
    RestClient coreSyncRestClient(CoreSyncProperties properties) {
        return RestClient.builder()
                .baseUrl(properties.baseUrl())
                .build();
    }
}
