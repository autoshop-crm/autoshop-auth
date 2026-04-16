package com.vladko.autoshopauth.common.exception;

public class TokenBlacklistedException extends RuntimeException {

    public TokenBlacklistedException(String message) {
        super(message);
    }
}
