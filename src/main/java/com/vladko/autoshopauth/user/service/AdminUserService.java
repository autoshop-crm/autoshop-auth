package com.vladko.autoshopauth.user.service;

import com.vladko.autoshopauth.common.exception.InvalidRoleAssignmentException;
import com.vladko.autoshopauth.common.exception.RoleNotFoundException;
import com.vladko.autoshopauth.common.exception.UserAlreadyExistsException;
import com.vladko.autoshopauth.role.entity.Role;
import com.vladko.autoshopauth.role.entity.RoleName;
import com.vladko.autoshopauth.role.repository.RoleRepository;
import com.vladko.autoshopauth.user.dto.AdminUserCreateRequest;
import com.vladko.autoshopauth.user.dto.UserResponse;
import com.vladko.autoshopauth.user.entity.User;
import com.vladko.autoshopauth.user.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Locale;
import java.util.Set;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class AdminUserService {

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;

    @Transactional
    public UserResponse createUser(AdminUserCreateRequest request) {
        validateStaffRoles(request.roles());

        String normalizedEmail = request.email().trim().toLowerCase(Locale.ROOT);
        if (userRepository.existsByEmail(normalizedEmail)) {
            throw new UserAlreadyExistsException("User with this email already exists");
        }

        Set<Role> roles = request.roles()
                .stream()
                .map(this::findRole)
                .collect(Collectors.toSet());

        User user = User.builder()
                .email(normalizedEmail)
                .passwordHash(passwordEncoder.encode(request.password()))
                .firstName(normalizeOptionalText(request.firstName()))
                .lastName(normalizeOptionalText(request.lastName()))
                .active(true)
                .roles(roles)
                .build();

        return toResponse(userRepository.save(user));
    }

    private void validateStaffRoles(Set<RoleName> roles) {
        if (roles == null || roles.isEmpty()) {
            throw new InvalidRoleAssignmentException("At least one staff role is required");
        }
        if (roles.contains(RoleName.CLIENT)) {
            throw new InvalidRoleAssignmentException("CLIENT users must be created through public registration");
        }
    }

    private Role findRole(RoleName roleName) {
        return roleRepository.findByName(roleName)
                .orElseThrow(() -> new RoleNotFoundException("Role not found: " + roleName));
    }

    private UserResponse toResponse(User user) {
        Set<String> roleNames = user.getRoles()
                .stream()
                .map(role -> role.getName().name())
                .collect(Collectors.toSet());

        return new UserResponse(
                user.getId(),
                user.getEmail(),
                roleNames,
                user.isActive(),
                user.getCreatedAt()
        );
    }

    private String normalizeOptionalText(String value) {
        if (value == null) {
            return null;
        }

        String trimmed = value.trim();
        return trimmed.isEmpty() ? null : trimmed;
    }
}
