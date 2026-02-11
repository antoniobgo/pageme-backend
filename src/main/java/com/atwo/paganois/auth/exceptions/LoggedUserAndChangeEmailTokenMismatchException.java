package com.atwo.paganois.auth.exceptions;

public class LoggedUserAndChangeEmailTokenMismatchException extends RuntimeException {
    public LoggedUserAndChangeEmailTokenMismatchException(String message) {
        super(message);
    }
}
