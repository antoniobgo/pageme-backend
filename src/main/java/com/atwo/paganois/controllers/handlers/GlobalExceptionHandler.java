package com.atwo.paganois.controllers.handlers;

import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import com.atwo.paganois.dtos.CustomErrorResponse;
import com.atwo.paganois.exceptions.ExpiredTokenException;
import com.atwo.paganois.exceptions.InvalidTokenException;
import com.atwo.paganois.exceptions.InvalidTokenTypeException;
import com.atwo.paganois.exceptions.LoggedUserAndChangeEmailTokenMismatchException;
import com.atwo.paganois.exceptions.TokenNotFoundException;
import com.atwo.paganois.exceptions.UserAlreadyExistsException;
import com.atwo.paganois.exceptions.UserNotVerifiedOrNotEnabledException;
import com.atwo.paganois.exceptions.WrongPasswordException;
import jakarta.servlet.http.HttpServletRequest;

@RestControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler(BadCredentialsException.class)
    public ResponseEntity<CustomErrorResponse> handleBadCredentials(BadCredentialsException e,
            HttpServletRequest request) {
        HttpStatus status = HttpStatus.UNAUTHORIZED;
        CustomErrorResponse err = new CustomErrorResponse(Instant.now(), status.value(),
                e.getMessage(), request.getRequestURI());
        return ResponseEntity.status(status).body(err);
    }

    @ExceptionHandler(DisabledException.class)
    public ResponseEntity<CustomErrorResponse> handleDisabled(DisabledException e,
            HttpServletRequest request) {
        HttpStatus status = HttpStatus.FORBIDDEN;
        CustomErrorResponse err = new CustomErrorResponse(Instant.now(), status.value(),
                e.getMessage(), request.getRequestURI());
        return ResponseEntity.status(status).body(err);
    }

    @ExceptionHandler(UsernameNotFoundException.class)
    public ResponseEntity<CustomErrorResponse> handleUserNotFound(UsernameNotFoundException e,
            HttpServletRequest request) {
        HttpStatus status = HttpStatus.NOT_FOUND;
        CustomErrorResponse err = new CustomErrorResponse(Instant.now(), status.value(),
                e.getMessage(), request.getRequestURI());
        return ResponseEntity.status(status).body(err);
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<Map<String, String>> handleValidationExceptions(
            MethodArgumentNotValidException ex) {
        Map<String, String> errors = new HashMap<>();
        ex.getBindingResult().getAllErrors().forEach((error) -> {
            String fieldName = ((FieldError) error).getField();
            String errorMessage = error.getDefaultMessage();
            errors.put(fieldName, errorMessage);
        });
        return ResponseEntity.badRequest().body(errors);
    }

    @ExceptionHandler(UserAlreadyExistsException.class)
    public ResponseEntity<CustomErrorResponse> handleUserAlreadyExists(UserAlreadyExistsException e,
            HttpServletRequest request) {
        HttpStatus status = HttpStatus.CONFLICT;
        CustomErrorResponse err = new CustomErrorResponse(Instant.now(), status.value(),
                e.getMessage(), request.getRequestURI());
        return ResponseEntity.status(status).body(err);
    }

    @ExceptionHandler(UserNotVerifiedOrNotEnabledException.class)
    public ResponseEntity<CustomErrorResponse> handleUserNotVerifiedOrNotEnabledException(
            UserNotVerifiedOrNotEnabledException e, HttpServletRequest request) {
        HttpStatus status = HttpStatus.FORBIDDEN;
        CustomErrorResponse err = new CustomErrorResponse(Instant.now(), status.value(),
                e.getMessage(), request.getRequestURI());
        return ResponseEntity.status(status).body(err);
    }

    @ExceptionHandler(InvalidTokenException.class)
    public ResponseEntity<CustomErrorResponse> handleInvalidTokenException(InvalidTokenException e,
            HttpServletRequest request) {
        HttpStatus status = HttpStatus.UNAUTHORIZED;
        CustomErrorResponse err = new CustomErrorResponse(Instant.now(), status.value(),
                e.getMessage(), request.getRequestURI());
        return ResponseEntity.status(status).body(err);
    }

    @ExceptionHandler(TokenNotFoundException.class)
    public ResponseEntity<CustomErrorResponse> handleTokenNotFoundException(
            TokenNotFoundException e, HttpServletRequest request) {
        HttpStatus status = HttpStatus.NOT_FOUND;
        CustomErrorResponse err = new CustomErrorResponse(Instant.now(), status.value(),
                e.getMessage(), request.getRequestURI());
        return ResponseEntity.status(status).body(err);
    }

    @ExceptionHandler(InvalidTokenTypeException.class)
    public ResponseEntity<CustomErrorResponse> handleInvalidTokenTypeException(
            InvalidTokenTypeException e, HttpServletRequest request) {
        HttpStatus status = HttpStatus.BAD_REQUEST;
        CustomErrorResponse err = new CustomErrorResponse(Instant.now(), status.value(),
                e.getMessage(), request.getRequestURI());
        return ResponseEntity.status(status).body(err);
    }

    @ExceptionHandler(ExpiredTokenException.class)
    public ResponseEntity<CustomErrorResponse> handleExpiredTokenException(ExpiredTokenException e,
            HttpServletRequest request) {
        HttpStatus status = HttpStatus.GONE;
        CustomErrorResponse err = new CustomErrorResponse(Instant.now(), status.value(),
                e.getMessage(), request.getRequestURI());
        return ResponseEntity.status(status).body(err);
    }

    @ExceptionHandler(WrongPasswordException.class)
    public ResponseEntity<CustomErrorResponse> handleWrongPasswordException(
            WrongPasswordException e, HttpServletRequest request) {
        HttpStatus status = HttpStatus.UNAUTHORIZED;
        CustomErrorResponse err = new CustomErrorResponse(Instant.now(), status.value(),
                e.getMessage(), request.getRequestURI());
        return ResponseEntity.status(status).body(err);
    }

    @ExceptionHandler(LoggedUserAndChangeEmailTokenMismatchException.class)
    public ResponseEntity<CustomErrorResponse> handleLoggedUserAndChangeEmailTokenMismatchException(
            LoggedUserAndChangeEmailTokenMismatchException e, HttpServletRequest request) {
        HttpStatus status = HttpStatus.UNAUTHORIZED;
        CustomErrorResponse err = new CustomErrorResponse(Instant.now(), status.value(),
                e.getMessage(), request.getRequestURI());
        return ResponseEntity.status(status).body(err);
    }

    // TODO: fazer esse general handler

    // @ExceptionHandler(Exception.class)
    // public ResponseEntity<CustomErrorResponse> handleGeneral(Exception e) {
    // e.printStackTrace(); // Log do erro
    // return ResponseEntity
    // .status(HttpStatus.INTERNAL_SERVER_ERROR)
    // .body(new CustomErrorResponse("An unexpected error occurred"));
    // }
}
