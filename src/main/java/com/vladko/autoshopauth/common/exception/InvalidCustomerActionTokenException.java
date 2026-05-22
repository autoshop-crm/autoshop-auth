package com.vladko.autoshopauth.common.exception;

public class InvalidCustomerActionTokenException extends RuntimeException {

    public InvalidCustomerActionTokenException(String message) {
        super(message);
    }
}
