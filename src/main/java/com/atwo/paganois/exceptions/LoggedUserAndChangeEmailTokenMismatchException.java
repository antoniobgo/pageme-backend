package com.atwo.paganois.exceptions;

public class LoggedUserAndChangeEmailTokenMismatchException extends RuntimeException {
    public LoggedUserAndChangeEmailTokenMismatchException(String message) {
        super(message);
    }
}
