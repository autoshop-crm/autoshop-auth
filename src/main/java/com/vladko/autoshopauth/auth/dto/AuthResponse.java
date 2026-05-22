package com.vladko.autoshopauth.auth.dto;

import java.time.Instant;
import java.util.Set;

public record AuthResponse(
        Long authUserId,
        Long userId,
        String email,
        String phoneNumber,
        String firstName,
        String lastName,
        Set<String> roles,
        String accessToken,
        String refreshToken,
        Instant expiresAt,
        boolean emailVerified,
        String accountStatus,
        String tokenType,
        long accessExpiresIn,
        long refreshExpiresIn
) {
}
