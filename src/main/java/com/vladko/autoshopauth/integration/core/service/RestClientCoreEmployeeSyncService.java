package com.vladko.autoshopauth.integration.core.service;

import com.vladko.autoshopauth.integration.core.config.CoreSyncProperties;
import com.vladko.autoshopauth.integration.core.dto.CoreEmployeeSyncRequest;
import com.vladko.autoshopauth.user.entity.User;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestClient;

import java.util.Set;
import java.util.stream.Collectors;

@Slf4j
@Service
@RequiredArgsConstructor
public class RestClientCoreEmployeeSyncService implements CoreEmployeeSyncService {

    private final @Qualifier("coreSyncRestClient") RestClient coreSyncRestClient;
    private final CoreSyncProperties coreSyncProperties;

    @Override
    public void syncStaffUser(User user) {
        Set<String> roles = user.getRoles().stream()
                .map(role -> role.getName().name())
                .collect(Collectors.toSet());

        try {
            coreSyncRestClient.post()
                    .uri("/api/internal/employees/sync")
                    .header("X-Employee-Sync-Token", coreSyncProperties.syncToken())
                    .body(new CoreEmployeeSyncRequest(
                            user.getEmail(),
                            user.getFirstName(),
                            user.getLastName(),
                            roles,
                            user.isActive()
                    ))
                    .retrieve()
                    .toBodilessEntity();
        } catch (RestClientException exception) {
            log.warn("Failed to sync staff user '{}' to core: {}", user.getEmail(), exception.getMessage());
        }
    }
}
