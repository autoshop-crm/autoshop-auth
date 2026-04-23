package com.vladko.autoshopauth.user.dto;

import java.time.Instant;
import java.util.Set;

public record UserResponse(
        Long id,
        String email,
        Set<String> roles,
        boolean active,
        Instant createdAt
) {
}
