package com.vladko.autoshopauth.common.exception;

public class RefreshTokenOwnershipException extends RuntimeException {

    public RefreshTokenOwnershipException(String message) {
        super(message);
    }
}
