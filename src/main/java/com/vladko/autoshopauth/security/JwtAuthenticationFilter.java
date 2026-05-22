package com.vladko.autoshopauth.security;

import com.vladko.autoshopauth.common.exception.RedisUnavailableException;
import com.vladko.autoshopauth.common.exception.TokenBlacklistedException;
import com.vladko.autoshopauth.common.exception.TokenValidationException;
import com.vladko.autoshopauth.user.entity.User;
import com.vladko.autoshopauth.user.repository.UserRepository;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.stream.Collectors;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.servlet.HandlerExceptionResolver;

@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private static final RequestMatcher PUBLIC_ENDPOINTS = new OrRequestMatcher(
            new AntPathRequestMatcher("/api/auth/register"),
            new AntPathRequestMatcher("/api/auth/login"),
            new AntPathRequestMatcher("/api/auth/refresh"),
            new AntPathRequestMatcher("/api/auth/customers/register", "POST"),
            new AntPathRequestMatcher("/api/auth/customers/login", "POST"),
            new AntPathRequestMatcher("/api/auth/customers/refresh", "POST"),
            new AntPathRequestMatcher("/api/auth/customers/password/forgot", "POST"),
            new AntPathRequestMatcher("/api/auth/customers/password/reset", "POST"),
            new AntPathRequestMatcher("/api/auth/customers/email/verify", "POST")
    );

    private final JwtService jwtService;
    private final AccessTokenBlacklistService blacklistService;
    private final UserRepository userRepository;
    private final AuthenticationEntryPoint authenticationEntryPoint;
    private final HandlerExceptionResolver handlerExceptionResolver;

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain
    ) throws ServletException, IOException {
        String authorizationHeader = request.getHeader(HttpHeaders.AUTHORIZATION);
        if (!StringUtils.hasText(authorizationHeader) || !authorizationHeader.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }

        String token = authorizationHeader.substring(7).trim();
        if (!StringUtils.hasText(token)) {
            if (isPublicEndpoint(request)) {
                filterChain.doFilter(request, response);
                return;
            }
            authenticationEntryPoint.commence(request, response, new TokenAuthenticationException("Bearer token is missing"));
            return;
        }

        try {
            AccessTokenClaims claims = jwtService.parseAccessToken(token);
            if (blacklistService.isBlacklisted(claims.jti())) {
                throw new TokenBlacklistedException("Access token is revoked");
            }

            User user = userRepository.findById(claims.userId())
                    .orElseThrow(() -> new TokenValidationException("Access token is invalid"));

            if (!user.isActive()) {
                throw new TokenValidationException("Access token is invalid");
            }

            AuthenticatedAccessToken principal = new AuthenticatedAccessToken(
                    claims.userId(),
                    claims.email(),
                    claims.roles(),
                    claims.type(),
                    claims.jti(),
                    claims.expiresAt()
            );

            UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
                    principal,
                    token,
                    claims.roles().stream()
                            .map(role -> new SimpleGrantedAuthority("ROLE_" + role))
                            .collect(Collectors.toSet())
            );

            SecurityContextHolder.getContext().setAuthentication(authentication);
            filterChain.doFilter(request, response);
        } catch (RedisUnavailableException exception) {
            SecurityContextHolder.clearContext();
            handlerExceptionResolver.resolveException(request, response, null, exception);
        } catch (TokenValidationException | TokenBlacklistedException exception) {
            SecurityContextHolder.clearContext();
            if (isPublicEndpoint(request)) {
                filterChain.doFilter(request, response);
                return;
            }
            authenticationEntryPoint.commence(request, response, new TokenAuthenticationException(exception.getMessage(), exception));
        }
    }

    private boolean isPublicEndpoint(HttpServletRequest request) {
        return PUBLIC_ENDPOINTS.matches(request);
    }
}
