package com.vladko.autoshopauth.auth.dto;

import java.time.Instant;
import java.util.Set;

public record TokenValidationResponse(
        boolean valid,
        Long userId,
        String email,
        Set<String> roles,
        String tokenType,
        String jti,
        Instant expiresAt,
        String message
) {

    public static TokenValidationResponse valid(
            Long userId,
            String email,
            Set<String> roles,
            String tokenType,
            String jti,
            Instant expiresAt
    ) {
        return new TokenValidationResponse(true, userId, email, roles, tokenType, jti, expiresAt, null);
    }

    public static TokenValidationResponse invalid(String message) {
        return new TokenValidationResponse(false, null, null, null, null, null, null, message);
    }
}
