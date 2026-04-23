package com.vladko.autoshopauth.auth.controller;

import com.vladko.autoshopauth.auth.dto.AuthResponse;
import com.vladko.autoshopauth.auth.dto.CurrentUserResponse;
import com.vladko.autoshopauth.auth.dto.LoginRequest;
import com.vladko.autoshopauth.auth.dto.LogoutRequest;
import com.vladko.autoshopauth.auth.dto.RefreshTokenRequest;
import com.vladko.autoshopauth.auth.dto.RegisterRequest;
import com.vladko.autoshopauth.auth.dto.RegisterResponse;
import com.vladko.autoshopauth.auth.dto.TokenValidationResponse;
import com.vladko.autoshopauth.auth.service.AuthService;
import com.vladko.autoshopauth.security.AuthenticatedAccessToken;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;

    @PostMapping("/register")
    public ResponseEntity<RegisterResponse> register(@Valid @RequestBody RegisterRequest request) {
        return ResponseEntity.status(HttpStatus.CREATED).body(authService.register(request));
    }

    @PostMapping("/login")
    public ResponseEntity<AuthResponse> login(@Valid @RequestBody LoginRequest request) {
        return ResponseEntity.ok(authService.login(request));
    }

    @PostMapping("/refresh")
    public ResponseEntity<AuthResponse> refresh(@Valid @RequestBody RefreshTokenRequest request) {
        return ResponseEntity.ok(authService.refresh(request));
    }

    @PostMapping("/logout")
    public ResponseEntity<Void> logout(
            @AuthenticationPrincipal AuthenticatedAccessToken authenticatedAccessToken,
            @Valid @RequestBody LogoutRequest request
    ) {
        authService.logout(authenticatedAccessToken, request);
        return ResponseEntity.ok().build();
    }

    @PostMapping("/validate")
    public ResponseEntity<TokenValidationResponse> validate(
            @AuthenticationPrincipal AuthenticatedAccessToken authenticatedAccessToken
    ) {
        return ResponseEntity.ok(authService.validate(authenticatedAccessToken));
    }

    @PostMapping("/verify-token")
    public ResponseEntity<TokenValidationResponse> verifyToken(
            @AuthenticationPrincipal AuthenticatedAccessToken authenticatedAccessToken
    ) {
        return ResponseEntity.ok(authService.validate(authenticatedAccessToken));
    }

    @GetMapping("/me")
    public ResponseEntity<CurrentUserResponse> me(
            @AuthenticationPrincipal AuthenticatedAccessToken authenticatedAccessToken
    ) {
        return ResponseEntity.ok(authService.currentUser(authenticatedAccessToken));
    }
}
