package com.vladko.autoshopauth.security;

import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Service;

@Service
@Profile("test")
public class InMemoryAccessTokenBlacklistService implements AccessTokenBlacklistService {

    private final Map<String, Instant> blacklist = new ConcurrentHashMap<>();

    @Override
    public void blacklistAccessToken(String jti, Instant expiresAt) {
        blacklist.put(jti, expiresAt);
    }

    @Override
    public boolean isBlacklisted(String jti) {
        Instant expiresAt = blacklist.get(jti);
        if (expiresAt == null) {
            return false;
        }

        if (expiresAt.isBefore(Instant.now())) {
            blacklist.remove(jti);
            return false;
        }

        return true;
    }
}
