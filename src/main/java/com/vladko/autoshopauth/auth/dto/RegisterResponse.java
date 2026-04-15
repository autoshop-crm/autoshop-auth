package com.vladko.autoshopauth.auth.dto;

import java.time.Instant;
import java.util.Set;

public record RegisterResponse(
        Long id,
        String email,
        Set<String> roles,
        Instant createdAt
) {
}
