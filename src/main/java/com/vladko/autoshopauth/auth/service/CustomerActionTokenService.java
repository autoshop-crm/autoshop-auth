package com.vladko.autoshopauth.auth.service;

import com.vladko.autoshopauth.common.exception.InvalidCustomerActionTokenException;
import com.vladko.autoshopauth.token.entity.CustomerActionToken;
import com.vladko.autoshopauth.token.entity.CustomerActionTokenType;
import com.vladko.autoshopauth.token.repository.CustomerActionTokenRepository;
import com.vladko.autoshopauth.user.entity.User;
import java.time.Duration;
import java.time.Instant;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
public class CustomerActionTokenService {

    private static final Duration PASSWORD_RESET_TTL = Duration.ofHours(1);
    private static final Duration EMAIL_VERIFICATION_TTL = Duration.ofDays(1);

    private final CustomerActionTokenRepository customerActionTokenRepository;

    @Transactional
    public CustomerActionToken createPasswordResetToken(User user) {
        invalidateActiveTokens(user.getId(), CustomerActionTokenType.PASSWORD_RESET);
        return customerActionTokenRepository.save(CustomerActionToken.builder()
                .user(user)
                .token(UUID.randomUUID().toString())
                .type(CustomerActionTokenType.PASSWORD_RESET)
                .expiresAt(Instant.now().plus(PASSWORD_RESET_TTL))
                .used(false)
                .build());
    }

    @Transactional
    public CustomerActionToken createEmailVerificationToken(User user) {
        invalidateActiveTokens(user.getId(), CustomerActionTokenType.EMAIL_VERIFICATION);
        return customerActionTokenRepository.save(CustomerActionToken.builder()
                .user(user)
                .token(UUID.randomUUID().toString())
                .type(CustomerActionTokenType.EMAIL_VERIFICATION)
                .expiresAt(Instant.now().plus(EMAIL_VERIFICATION_TTL))
                .used(false)
                .build());
    }

    @Transactional(readOnly = true)
    public CustomerActionToken validate(String rawToken, CustomerActionTokenType type) {
        CustomerActionToken token = customerActionTokenRepository.findByTokenAndType(rawToken.trim(), type)
                .orElseThrow(() -> new InvalidCustomerActionTokenException(message(type)));

        if (token.isUsed() || token.getExpiresAt().isBefore(Instant.now()) || !token.getUser().isActive()) {
            throw new InvalidCustomerActionTokenException(message(type));
        }

        return token;
    }

    @Transactional
    public void markUsed(CustomerActionToken token) {
        token.setUsed(true);
        customerActionTokenRepository.save(token);
    }

    @Transactional(readOnly = true)
    public CustomerActionToken findLatestForUser(Long userId, CustomerActionTokenType type) {
        return customerActionTokenRepository.findTopByUserIdAndTypeOrderByCreatedAtDesc(userId, type)
                .orElseThrow(() -> new InvalidCustomerActionTokenException(message(type)));
    }

    private void invalidateActiveTokens(Long userId, CustomerActionTokenType type) {
        for (CustomerActionToken token : customerActionTokenRepository.findAllByUserIdAndTypeAndUsedFalse(userId, type)) {
            token.setUsed(true);
        }
    }

    private String message(CustomerActionTokenType type) {
        return switch (type) {
            case PASSWORD_RESET -> "Password reset token is invalid";
            case EMAIL_VERIFICATION -> "Email verification token is invalid";
        };
    }
}
