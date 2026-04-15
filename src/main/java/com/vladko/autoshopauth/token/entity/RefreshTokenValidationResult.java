package com.vladko.autoshopauth.token.entity;

import com.vladko.autoshopauth.user.entity.User;

public record RefreshTokenValidationResult(
        RefreshToken refreshToken,
        User user
) {
}
