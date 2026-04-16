package com.vladko.autoshopauth.security;

import org.springframework.security.core.AuthenticationException;

public class TokenAuthenticationException extends AuthenticationException {

    public TokenAuthenticationException(String message) {
        super(message);
    }

    public TokenAuthenticationException(String message, Throwable cause) {
        super(message, cause);
    }
}
