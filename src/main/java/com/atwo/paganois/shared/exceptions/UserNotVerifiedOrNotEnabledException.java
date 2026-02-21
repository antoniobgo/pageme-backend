package com.atwo.paganois.shared.exceptions;

public class UserNotVerifiedOrNotEnabledException extends RuntimeException {
    public UserNotVerifiedOrNotEnabledException(String message) {
        super(message);
    }
}
