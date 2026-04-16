package com.vladko.autoshopauth.security;

import java.time.Instant;

public interface AccessTokenBlacklistService {

    void blacklistAccessToken(String jti, Instant expiresAt);

    boolean isBlacklisted(String jti);
}
