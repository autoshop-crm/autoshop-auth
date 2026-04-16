package com.vladko.autoshopauth.security;

import com.vladko.autoshopauth.common.exception.TokenValidationException;
import com.vladko.autoshopauth.config.AppSecurityProperties;
import com.vladko.autoshopauth.user.entity.User;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import javax.crypto.SecretKey;
import org.springframework.stereotype.Service;

@Service
public class JwtService {

    private final SecretKey secretKey;
    private final AppSecurityProperties securityProperties;

    public JwtService(AppSecurityProperties securityProperties) {
        this.securityProperties = securityProperties;
        this.secretKey = Keys.hmacShaKeyFor(
                securityProperties.getJwt().getSecret().getBytes(StandardCharsets.UTF_8)
        );
    }

    public String generateAccessToken(User user) {
        Instant now = Instant.now();
        Instant expiresAt = now.plus(securityProperties.getJwt().getAccessTtl());
        List<String> roles = user.getRoles().stream().map(role -> role.getName().name()).toList();

        return Jwts.builder()
                .id(UUID.randomUUID().toString())
                .subject(String.valueOf(user.getId()))
                .claim("email", user.getEmail())
                .claim("roles", roles)
                .claim("type", "access")
                .issuedAt(Date.from(now))
                .expiration(Date.from(expiresAt))
                .signWith(secretKey)
                .compact();
    }

    public AccessTokenClaims parseAccessToken(String token) {
        try {
            Claims claims = Jwts.parser()
                    .verifyWith(secretKey)
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();

            String type = claims.get("type", String.class);
            List<?> rawRoles = claims.get("roles", List.class);
            if (!"access".equals(type)
                    || claims.getId() == null
                    || claims.getSubject() == null
                    || claims.getIssuedAt() == null
                    || claims.getExpiration() == null
                    || rawRoles == null) {
                throw new TokenValidationException("Access token is invalid");
            }

            Set<String> roles = rawRoles.stream()
                    .map(String::valueOf)
                    .collect(java.util.stream.Collectors.toSet());

            return new AccessTokenClaims(
                    claims.getId(),
                    Long.valueOf(claims.getSubject()),
                    claims.get("email", String.class),
                    roles,
                    type,
                    claims.getIssuedAt().toInstant(),
                    claims.getExpiration().toInstant()
            );
        } catch (JwtException | IllegalArgumentException exception) {
            throw new TokenValidationException("Access token is invalid", exception);
        }
    }
}
