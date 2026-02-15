package com.atwo.paganois.shared.exceptions.handlers;

import java.time.Instant;
import java.util.Map;
import java.util.stream.Collectors;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import com.atwo.paganois.auth.exceptions.ExpiredTokenException;
import com.atwo.paganois.auth.exceptions.InvalidTokenException;
import com.atwo.paganois.auth.exceptions.InvalidTokenTypeException;
import com.atwo.paganois.auth.exceptions.LoggedUserAndChangeEmailTokenMismatchException;
import com.atwo.paganois.auth.exceptions.TokenNotFoundException;
import com.atwo.paganois.auth.exceptions.UserAlreadyExistsException;
import com.atwo.paganois.auth.exceptions.UserNotVerifiedOrNotEnabledException;
import com.atwo.paganois.auth.exceptions.WrongPasswordException;
import com.atwo.paganois.shared.dtos.CustomErrorResponse;
import jakarta.servlet.http.HttpServletRequest;

@RestControllerAdvice
public class GlobalExceptionHandler {
    private static final Logger logger = LoggerFactory.getLogger(GlobalExceptionHandler.class);

    @ExceptionHandler(BadCredentialsException.class)
    public ResponseEntity<CustomErrorResponse> handleBadCredentials(BadCredentialsException e,
            HttpServletRequest request) {
        HttpStatus status = HttpStatus.UNAUTHORIZED;
        return buildErrorResponse(e, status, request);
    }

    @ExceptionHandler(DisabledException.class)
    public ResponseEntity<CustomErrorResponse> handleDisabled(DisabledException e,
            HttpServletRequest request) {
        HttpStatus status = HttpStatus.FORBIDDEN;
        return buildErrorResponse(e, status, request);
    }

    @ExceptionHandler(UsernameNotFoundException.class)
    public ResponseEntity<CustomErrorResponse> handleUserNotFound(UsernameNotFoundException e,
            HttpServletRequest request) {
        HttpStatus status = HttpStatus.NOT_FOUND;
        return buildErrorResponse(e, status, request);
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<CustomErrorResponse> handleValidationExceptions(
            MethodArgumentNotValidException ex, HttpServletRequest request) {
        Map<String, String> errors = ex.getBindingResult().getAllErrors().stream()
                .collect(Collectors.toMap(error -> ((FieldError) error).getField(),
                        error -> error.getDefaultMessage()));

        CustomErrorResponse err = new CustomErrorResponse(Instant.now(),
                HttpStatus.BAD_REQUEST.value(), errors.toString(), // ou serialize como JSON
                request.getRequestURI());
        return ResponseEntity.badRequest().body(err);
    }

    @ExceptionHandler(UserAlreadyExistsException.class)
    public ResponseEntity<CustomErrorResponse> handleUserAlreadyExists(UserAlreadyExistsException e,
            HttpServletRequest request) {
        HttpStatus status = HttpStatus.CONFLICT;
        return buildErrorResponse(e, status, request);
    }

    @ExceptionHandler(UserNotVerifiedOrNotEnabledException.class)
    public ResponseEntity<CustomErrorResponse> handleUserNotVerifiedOrNotEnabledException(
            UserNotVerifiedOrNotEnabledException e, HttpServletRequest request) {
        HttpStatus status = HttpStatus.FORBIDDEN;
        return buildErrorResponse(e, status, request);
    }

    @ExceptionHandler(InvalidTokenException.class)
    public ResponseEntity<CustomErrorResponse> handleInvalidTokenException(InvalidTokenException e,
            HttpServletRequest request) {
        HttpStatus status = HttpStatus.UNAUTHORIZED;
        return buildErrorResponse(e, status, request);
    }

    @ExceptionHandler(TokenNotFoundException.class)
    public ResponseEntity<CustomErrorResponse> handleTokenNotFoundException(
            TokenNotFoundException e, HttpServletRequest request) {
        HttpStatus status = HttpStatus.NOT_FOUND;
        return buildErrorResponse(e, status, request);
    }

    @ExceptionHandler(InvalidTokenTypeException.class)
    public ResponseEntity<CustomErrorResponse> handleInvalidTokenTypeException(
            InvalidTokenTypeException e, HttpServletRequest request) {
        HttpStatus status = HttpStatus.BAD_REQUEST;
        return buildErrorResponse(e, status, request);
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

    @ExceptionHandler(Exception.class)
    public ResponseEntity<CustomErrorResponse> handleGeneral(Exception e,
            HttpServletRequest request) {
        logger.error("Erro inesperado capturado", e);
        return buildErrorResponse(new RuntimeException("Erro interno do servidor"),
                HttpStatus.INTERNAL_SERVER_ERROR, request);
    }

    private ResponseEntity<CustomErrorResponse> buildErrorResponse(Exception e, HttpStatus status,
            HttpServletRequest request) {
        CustomErrorResponse err = new CustomErrorResponse(Instant.now(), status.value(),
                e.getMessage(), request.getRequestURI());
        return ResponseEntity.status(status).body(err);
    }
}
