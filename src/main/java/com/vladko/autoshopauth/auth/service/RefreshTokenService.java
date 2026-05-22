package com.vladko.autoshopauth.auth.service;

import com.vladko.autoshopauth.common.exception.InvalidRefreshTokenException;
import com.vladko.autoshopauth.common.exception.RefreshTokenOwnershipException;
import com.vladko.autoshopauth.config.AppSecurityProperties;
import com.vladko.autoshopauth.token.entity.RefreshToken;
import com.vladko.autoshopauth.token.entity.RefreshTokenValidationResult;
import com.vladko.autoshopauth.token.repository.RefreshTokenRepository;
import com.vladko.autoshopauth.user.entity.User;
import java.time.Instant;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
public class RefreshTokenService {

    private final RefreshTokenRepository refreshTokenRepository;
    private final AppSecurityProperties securityProperties;

    @Transactional
    public RefreshToken create(User user) {
        RefreshToken refreshToken = RefreshToken.builder()
                .user(user)
                .token(UUID.randomUUID().toString())
                .expiresAt(Instant.now().plus(securityProperties.getJwt().getRefreshTtl()))
                .revoked(false)
                .build();

        return refreshTokenRepository.save(refreshToken);
    }

    @Transactional(readOnly = true)
    public RefreshTokenValidationResult validate(String rawToken) {
        RefreshToken refreshToken = refreshTokenRepository.findByToken(rawToken)
                .orElseThrow(() -> new InvalidRefreshTokenException("Refresh token is invalid"));

        if (refreshToken.isRevoked() || refreshToken.getExpiresAt().isBefore(Instant.now())) {
            throw new InvalidRefreshTokenException("Refresh token is invalid");
        }

        if (!refreshToken.getUser().isActive()) {
            throw new InvalidRefreshTokenException("Refresh token is invalid");
        }

        return new RefreshTokenValidationResult(refreshToken, refreshToken.getUser());
    }

    @Transactional
    public void revoke(RefreshToken refreshToken) {
        refreshToken.setRevoked(true);
        refreshTokenRepository.save(refreshToken);
    }

    @Transactional
    public void revokeForLogout(String rawToken, Long userId) {
        refreshTokenRepository.findByToken(rawToken.trim()).ifPresent(refreshToken -> {
            if (!refreshToken.getUser().getId().equals(userId)) {
                throw new RefreshTokenOwnershipException("Refresh token does not belong to the current user");
            }

            if (!refreshToken.isRevoked()) {
                refreshToken.setRevoked(true);
                refreshTokenRepository.save(refreshToken);
            }
        });
    }

    @Transactional
    public void revokeAllForUser(Long userId) {
        for (RefreshToken refreshToken : refreshTokenRepository.findAllByUserId(userId)) {
            if (!refreshToken.isRevoked()) {
                refreshToken.setRevoked(true);
                refreshTokenRepository.save(refreshToken);
            }
        }
    }
}
