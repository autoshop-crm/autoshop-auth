package com.vladko.autoshopauth.auth.dto;

import java.util.Set;

public record AuthResponse(
        String accessToken,
        String refreshToken,
        String tokenType,
        long accessExpiresIn,
        long refreshExpiresIn,
        Long userId,
        String email,
        Set<String> roles
) {
}
