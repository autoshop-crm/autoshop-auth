package com.vladko.autoshopauth.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.vladko.autoshopauth.auth.dto.TokenValidationResponse;
import com.vladko.autoshopauth.common.exception.ErrorResponse;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.time.Instant;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class RestAuthenticationEntryPoint implements AuthenticationEntryPoint {

    private static final String VALIDATE_PATH = "/api/auth/validate";
    private static final String VERIFY_TOKEN_PATH = "/api/auth/verify-token";

    private final ObjectMapper objectMapper;

    @Override
    public void commence(
            HttpServletRequest request,
            HttpServletResponse response,
            AuthenticationException authException
    ) throws IOException, ServletException {
        response.setStatus(HttpStatus.UNAUTHORIZED.value());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);

        if (VALIDATE_PATH.equals(request.getRequestURI()) || VERIFY_TOKEN_PATH.equals(request.getRequestURI())) {
            objectMapper.writeValue(response.getWriter(), TokenValidationResponse.invalid(authException.getMessage()));
            return;
        }

        ErrorResponse errorResponse = new ErrorResponse(
                Instant.now(),
                HttpStatus.UNAUTHORIZED.value(),
                HttpStatus.UNAUTHORIZED.getReasonPhrase(),
                authException.getMessage(),
                request.getRequestURI()
        );
        objectMapper.writeValue(response.getWriter(), errorResponse);
    }
}
