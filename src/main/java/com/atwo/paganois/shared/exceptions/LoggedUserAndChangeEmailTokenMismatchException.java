package com.atwo.paganois.shared.exceptions;

public class LoggedUserAndChangeEmailTokenMismatchException extends RuntimeException {
    public LoggedUserAndChangeEmailTokenMismatchException(String message) {
        super(message);
    }
}
