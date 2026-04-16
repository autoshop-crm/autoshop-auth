package com.vladko.autoshopauth.security;

import java.time.Instant;
import java.util.Set;

public record AuthenticatedAccessToken(
        Long userId,
        String email,
        Set<String> roles,
        String tokenType,
        String jti,
        Instant expiresAt
) {
}
