package com.vladko.autoshopauth.security;

import java.time.Instant;
import java.util.Set;

public record AccessTokenClaims(
        String jti,
        Long userId,
        String email,
        Set<String> roles,
        String type,
        Instant issuedAt,
        Instant expiresAt
) {
}
