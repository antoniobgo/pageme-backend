package com.atwo.paganois.exceptions;

public class UserNotVerifiedOrNotEnabledException extends RuntimeException {
    public UserNotVerifiedOrNotEnabledException(String message) {
        super(message);
    }
}
