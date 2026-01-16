package com.atwo.paganois.controllers.handlers;

import com.atwo.paganois.dtos.CustomErrorResponse;
import com.atwo.paganois.exceptions.UserAlreadyExistsException;

import jakarta.servlet.http.HttpServletRequest;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

@RestControllerAdvice
public class GlobalExceptionHandler {

    // @ExceptionHandler(ForbiddenException.class)
    // public ResponseEntity<CustomError> forbidden(ForbiddenException e,
    // HttpServletRequest request) {
    // HttpStatus status = HttpStatus.FORBIDDEN;
    // CustomError err = new CustomError(Instant.now(), status.value(),
    // e.getMessage(), request.getRequestURI());
    // return ResponseEntity.status(status).body(err);
    // }
    //
    @ExceptionHandler(BadCredentialsException.class)
    public ResponseEntity<CustomErrorResponse> handleBadCredentials(BadCredentialsException e,
            HttpServletRequest request) {
        HttpStatus status = HttpStatus.FORBIDDEN;
        CustomErrorResponse err = new CustomErrorResponse(Instant.now(), status.value(), e.getMessage(),
                request.getRequestURI());
        return ResponseEntity.status(status).body(err);
    }

    @ExceptionHandler(DisabledException.class)
    public ResponseEntity<CustomErrorResponse> handleDisabled(DisabledException e, HttpServletRequest request) {
        HttpStatus status = HttpStatus.FORBIDDEN;
        CustomErrorResponse err = new CustomErrorResponse(Instant.now(), status.value(), e.getMessage(),
                request.getRequestURI());
        return ResponseEntity.status(status).body(err);
    }

    @ExceptionHandler(UsernameNotFoundException.class)
    public ResponseEntity<CustomErrorResponse> handleUserNotFound(UsernameNotFoundException e,
            HttpServletRequest request) {
        HttpStatus status = HttpStatus.NOT_FOUND;
        CustomErrorResponse err = new CustomErrorResponse(Instant.now(), status.value(), e.getMessage(),
                request.getRequestURI());
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
        CustomErrorResponse err = new CustomErrorResponse(Instant.now(), status.value(), e.getMessage(),
                request.getRequestURI());
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