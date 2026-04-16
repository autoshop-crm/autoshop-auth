package com.vladko.autoshopauth.security;

import com.vladko.autoshopauth.common.exception.RedisUnavailableException;
import java.time.Duration;
import java.time.Instant;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Profile;
import org.springframework.dao.DataAccessException;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

@Service
@Profile("!test")
@RequiredArgsConstructor
public class RedisAccessTokenBlacklistService implements AccessTokenBlacklistService {

    private static final String KEY_PREFIX = "blacklist:access:";

    private final StringRedisTemplate stringRedisTemplate;

    @Override
    public void blacklistAccessToken(String jti, Instant expiresAt) {
        Duration ttl = Duration.between(Instant.now(), expiresAt);
        if (ttl.isNegative() || ttl.isZero()) {
            return;
        }

        try {
            stringRedisTemplate.opsForValue().set(buildKey(jti), "true", ttl);
        } catch (DataAccessException exception) {
            throw new RedisUnavailableException("Redis is unavailable for token blacklist operation", exception);
        }
    }

    @Override
    public boolean isBlacklisted(String jti) {
        try {
            return Boolean.TRUE.equals(stringRedisTemplate.hasKey(buildKey(jti)));
        } catch (DataAccessException exception) {
            throw new RedisUnavailableException("Redis is unavailable for token blacklist check", exception);
        }
    }

    private String buildKey(String jti) {
        return KEY_PREFIX + jti;
    }
}
