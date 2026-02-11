package com.atwo.paganois.auth.exceptions;

public class UserNotVerifiedOrNotEnabledException extends RuntimeException {
    public UserNotVerifiedOrNotEnabledException(String message) {
        super(message);
    }
}
