package com.vladko.autoshopauth.auth.dto;

import java.time.Instant;
import java.util.Set;

public record CurrentUserResponse(
        Long userId,
        String email,
        Set<String> roles,
        Instant expiresAt
) {
}
