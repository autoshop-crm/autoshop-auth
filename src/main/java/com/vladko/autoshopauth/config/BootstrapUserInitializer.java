package com.vladko.autoshopauth.config;

import com.vladko.autoshopauth.common.exception.RoleNotFoundException;
import com.vladko.autoshopauth.integration.core.service.CoreEmployeeSyncService;
import com.vladko.autoshopauth.role.entity.Role;
import com.vladko.autoshopauth.role.repository.RoleRepository;
import com.vladko.autoshopauth.user.entity.AccountStatus;
import com.vladko.autoshopauth.user.entity.User;
import com.vladko.autoshopauth.user.repository.UserRepository;
import java.util.Locale;
import java.util.Set;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

@Component
@RequiredArgsConstructor
public class BootstrapUserInitializer implements ApplicationRunner {

    private final AppBootstrapProperties bootstrapProperties;
    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;
    private final CoreEmployeeSyncService coreEmployeeSyncService;

    @Override
    @Transactional
    public void run(ApplicationArguments args) {
        if (!bootstrapProperties.isEnabled()) {
            return;
        }

        String normalizedEmail = bootstrapProperties.getEmail().trim().toLowerCase(Locale.ROOT);
        if (userRepository.existsByEmail(normalizedEmail)) {
            return;
        }

        Role role = roleRepository.findByName(bootstrapProperties.getRole())
                .orElseThrow(() -> new RoleNotFoundException("Bootstrap role not found"));

        User user = User.builder()
                .email(normalizedEmail)
                .passwordHash(passwordEncoder.encode(bootstrapProperties.getPassword()))
                .firstName("Admin")
                .lastName("User")
                .emailVerified(true)
                .accountStatus(AccountStatus.ACTIVE)
                .active(true)
                .roles(Set.of(role))
                .build();

        User savedUser = userRepository.save(user);
        coreEmployeeSyncService.syncStaffUser(savedUser);
    }
}
