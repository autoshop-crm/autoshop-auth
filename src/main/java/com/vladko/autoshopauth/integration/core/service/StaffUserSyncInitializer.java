package com.vladko.autoshopauth.integration.core.service;

import com.vladko.autoshopauth.role.entity.RoleName;
import com.vladko.autoshopauth.user.entity.User;
import com.vladko.autoshopauth.user.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.stereotype.Component;

@Slf4j
@Component
@RequiredArgsConstructor
public class StaffUserSyncInitializer implements ApplicationRunner {

    private final UserRepository userRepository;
    private final CoreEmployeeSyncService coreEmployeeSyncService;

    @Override
    public void run(ApplicationArguments args) {
        for (User user : userRepository.findAll()) {
            boolean hasStaffRole = user.getRoles().stream()
                    .anyMatch(role -> role.getName() != RoleName.CLIENT);
            if (!hasStaffRole) {
                continue;
            }

            try {
                coreEmployeeSyncService.syncStaffUser(user);
            } catch (Exception exception) {
                log.warn("Failed to sync staff user '{}' to core: {}", user.getEmail(), exception.getMessage());
            }
        }
    }
}
