package com.vladko.autoshopauth.auth.controller;

import com.vladko.autoshopauth.auth.dto.AuthResponse;
import com.vladko.autoshopauth.auth.dto.ForgotPasswordRequest;
import com.vladko.autoshopauth.auth.dto.LoginRequest;
import com.vladko.autoshopauth.auth.dto.LogoutRequest;
import com.vladko.autoshopauth.auth.dto.RefreshTokenRequest;
import com.vladko.autoshopauth.auth.dto.RegisterRequest;
import com.vladko.autoshopauth.auth.dto.ResetPasswordRequest;
import com.vladko.autoshopauth.auth.dto.VerifyEmailRequest;
import com.vladko.autoshopauth.auth.service.AuthService;
import com.vladko.autoshopauth.security.AuthenticatedAccessToken;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/auth/customers")
@RequiredArgsConstructor
public class CustomerAuthController {

    private final AuthService authService;

    @PostMapping("/register")
    public ResponseEntity<AuthResponse> register(@Valid @RequestBody RegisterRequest request) {
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
        return ResponseEntity.noContent().build();
    }

    @PostMapping("/password/forgot")
    public ResponseEntity<Void> forgotPassword(@Valid @RequestBody ForgotPasswordRequest request) {
        authService.forgotPassword(request);
        return ResponseEntity.accepted().build();
    }

    @PostMapping("/password/reset")
    public ResponseEntity<Void> resetPassword(@Valid @RequestBody ResetPasswordRequest request) {
        authService.resetPassword(request);
        return ResponseEntity.noContent().build();
    }

    @PostMapping("/email/verify")
    public ResponseEntity<Void> verifyEmail(@Valid @RequestBody VerifyEmailRequest request) {
        authService.verifyEmail(request);
        return ResponseEntity.noContent().build();
    }
}
