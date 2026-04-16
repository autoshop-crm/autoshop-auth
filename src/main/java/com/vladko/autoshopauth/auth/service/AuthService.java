package com.vladko.autoshopauth.auth.service;

import com.vladko.autoshopauth.auth.dto.AuthResponse;
import com.vladko.autoshopauth.auth.dto.LoginRequest;
import com.vladko.autoshopauth.auth.dto.LogoutRequest;
import com.vladko.autoshopauth.auth.dto.RefreshTokenRequest;
import com.vladko.autoshopauth.auth.dto.RegisterRequest;
import com.vladko.autoshopauth.auth.dto.RegisterResponse;
import com.vladko.autoshopauth.auth.dto.TokenValidationResponse;
import com.vladko.autoshopauth.common.exception.InvalidCredentialsException;
import com.vladko.autoshopauth.common.exception.RoleNotFoundException;
import com.vladko.autoshopauth.common.exception.UserAlreadyExistsException;
import com.vladko.autoshopauth.config.AppSecurityProperties;
import com.vladko.autoshopauth.role.entity.Role;
import com.vladko.autoshopauth.role.entity.RoleName;
import com.vladko.autoshopauth.role.repository.RoleRepository;
import com.vladko.autoshopauth.security.AccessTokenBlacklistService;
import com.vladko.autoshopauth.security.AuthenticatedAccessToken;
import com.vladko.autoshopauth.security.JwtService;
import com.vladko.autoshopauth.token.entity.RefreshToken;
import com.vladko.autoshopauth.token.entity.RefreshTokenValidationResult;
import com.vladko.autoshopauth.user.entity.User;
import com.vladko.autoshopauth.user.repository.UserRepository;
import java.util.Locale;
import java.util.Set;
import java.util.stream.Collectors;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;
    private final JwtService jwtService;
    private final RefreshTokenService refreshTokenService;
    private final AppSecurityProperties securityProperties;
    private final AccessTokenBlacklistService blacklistService;

    @Transactional
    public RegisterResponse register(RegisterRequest request) {
        String normalizedEmail = normalizeEmail(request.email());
        if (userRepository.existsByEmail(normalizedEmail)) {
            throw new UserAlreadyExistsException("User with this email already exists");
        }

        Role clientRole = roleRepository.findByName(RoleName.CLIENT)
                .orElseThrow(() -> new RoleNotFoundException("Default CLIENT role not found"));

        User user = User.builder()
                .email(normalizedEmail)
                .passwordHash(passwordEncoder.encode(request.password()))
                .firstName(normalizeOptionalText(request.firstName()))
                .lastName(normalizeOptionalText(request.lastName()))
                .active(true)
                .roles(Set.of(clientRole))
                .build();

        User savedUser = userRepository.save(user);
        return new RegisterResponse(
                savedUser.getId(),
                savedUser.getEmail(),
                roleNames(savedUser),
                savedUser.getCreatedAt()
        );
    }

    @Transactional
    public AuthResponse login(LoginRequest request) {
        String normalizedEmail = normalizeEmail(request.email());
        authenticate(normalizedEmail, request.password());

        User user = userRepository.findByEmail(normalizedEmail)
                .orElseThrow(() -> new InvalidCredentialsException("Invalid email or password"));

        if (!user.isActive()) {
            throw new InvalidCredentialsException("Invalid email or password");
        }

        return issueTokens(user);
    }

    @Transactional
    public AuthResponse refresh(RefreshTokenRequest request) {
        RefreshTokenValidationResult validationResult = refreshTokenService.validate(request.refreshToken().trim());
        RefreshToken currentRefreshToken = validationResult.refreshToken();
        User user = validationResult.user();

        refreshTokenService.revoke(currentRefreshToken);
        return issueTokens(user);
    }

    @Transactional
    public void logout(AuthenticatedAccessToken authenticatedAccessToken, LogoutRequest request) {
        refreshTokenService.revokeForLogout(request.refreshToken(), authenticatedAccessToken.userId());
        blacklistService.blacklistAccessToken(authenticatedAccessToken.jti(), authenticatedAccessToken.expiresAt());
    }

    @Transactional(readOnly = true)
    public TokenValidationResponse validate(AuthenticatedAccessToken authenticatedAccessToken) {
        return TokenValidationResponse.valid(
                authenticatedAccessToken.userId(),
                authenticatedAccessToken.email(),
                authenticatedAccessToken.roles(),
                authenticatedAccessToken.tokenType(),
                authenticatedAccessToken.jti(),
                authenticatedAccessToken.expiresAt()
        );
    }

    private void authenticate(String email, String password) {
        try {
            authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(email, password)
            );
        } catch (BadCredentialsException | DisabledException exception) {
            throw new InvalidCredentialsException("Invalid email or password");
        } catch (AuthenticationException exception) {
            throw new InvalidCredentialsException("Invalid email or password");
        }
    }

    private AuthResponse issueTokens(User user) {
        RefreshToken refreshToken = refreshTokenService.create(user);
        String accessToken = jwtService.generateAccessToken(user);

        return new AuthResponse(
                accessToken,
                refreshToken.getToken(),
                "Bearer",
                securityProperties.getJwt().getAccessTtl().toSeconds(),
                securityProperties.getJwt().getRefreshTtl().toSeconds(),
                user.getId(),
                user.getEmail(),
                roleNames(user)
        );
    }

    private Set<String> roleNames(User user) {
        return user.getRoles()
                .stream()
                .map(role -> role.getName().name())
                .collect(Collectors.toSet());
    }

    private String normalizeEmail(String email) {
        return email.trim().toLowerCase(Locale.ROOT);
    }

    private String normalizeOptionalText(String value) {
        if (value == null) {
            return null;
        }

        String trimmed = value.trim();
        return trimmed.isEmpty() ? null : trimmed;
    }
}
