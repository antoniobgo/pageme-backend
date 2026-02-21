package com.atwo.paganois.shared.exceptions.handlers;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import java.time.Instant;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.validation.BindingResult;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import com.atwo.paganois.shared.dtos.CustomErrorResponse;
import com.atwo.paganois.shared.exceptions.EmailAlreadyTakenException;
import com.atwo.paganois.shared.exceptions.ExpiredTokenException;
import com.atwo.paganois.shared.exceptions.InvalidTokenException;
import com.atwo.paganois.shared.exceptions.InvalidTokenTypeException;
import com.atwo.paganois.shared.exceptions.LoggedUserAndChangeEmailTokenMismatchException;
import com.atwo.paganois.shared.exceptions.TokenNotFoundException;
import com.atwo.paganois.shared.exceptions.UserAlreadyExistsException;
import com.atwo.paganois.shared.exceptions.UserNotVerifiedOrNotEnabledException;
import com.atwo.paganois.shared.exceptions.WrongPasswordException;
import jakarta.servlet.http.HttpServletRequest;

/**
 * Unit tests for GlobalExceptionHandler
 * 
 * Tests exception mapping to HTTP status codes and error responses
 */
@DisplayName("GlobalExceptionHandler - Unit Tests")
class GlobalExceptionHandlerTest {

    private GlobalExceptionHandler exceptionHandler;
    private HttpServletRequest request;

    private static final String REQUEST_URI = "/api/test";

    @BeforeEach
    void setUp() {
        exceptionHandler = new GlobalExceptionHandler();
        request = mock(HttpServletRequest.class);
        when(request.getRequestURI()).thenReturn(REQUEST_URI);
    }

    // ========================================================================
    // TESTS: Authentication exceptions (401)
    // ========================================================================

    @Nested
    @DisplayName("Exceções de autenticação - 401 UNAUTHORIZED")
    class AuthenticationExceptionsTests {

        @Test
        @DisplayName("Deveria mapear BadCredentialsException para 401")
        void shouldMap_BadCredentialsException_To401() {
            // Arrange
            BadCredentialsException exception =
                    new BadCredentialsException("Credenciais inválidas");

            // Act
            ResponseEntity<CustomErrorResponse> response =
                    exceptionHandler.handleBadCredentials(exception, request);

            // Assert
            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
            assertThat(response.getBody()).isNotNull();
            assertThat(response.getBody().getStatus()).isEqualTo(401);
            assertThat(response.getBody().getError()).isEqualTo("Credenciais inválidas");
            assertThat(response.getBody().getPath()).isEqualTo(REQUEST_URI);
        }

        @Test
        @DisplayName("Deveria mapear InvalidTokenException para 401")
        void shouldMap_InvalidTokenException_To401() {
            // Arrange
            InvalidTokenException exception = new InvalidTokenException("Token inválido");

            // Act
            ResponseEntity<CustomErrorResponse> response =
                    exceptionHandler.handleInvalidTokenException(exception, request);

            // Assert
            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
            assertThat(response.getBody().getStatus()).isEqualTo(401);
            assertThat(response.getBody().getError()).isEqualTo("Token inválido");
        }

        @Test
        @DisplayName("Deveria mapear UsernameNotFoundException para 404")
        void shouldMap_UsernameNotFoundException_To401() {
            // Arrange
            UsernameNotFoundException exception =
                    new UsernameNotFoundException("Usuário não encontrado");

            // Act
            ResponseEntity<CustomErrorResponse> response =
                    exceptionHandler.handleUserNotFound(exception, request);

            // Assert
            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.NOT_FOUND);
            assertThat(response.getBody().getStatus()).isEqualTo(404);
        }
    }

    // ========================================================================
    // TESTS: Forbidden exceptions (403)
    // ========================================================================

    @Nested
    @DisplayName("Exceções de acesso negado - 403 FORBIDDEN")
    class ForbiddenExceptionsTests {

        @Test
        @DisplayName("Deveria mapear DisabledException para 403")
        void shouldMap_DisabledException_To403() {
            // Arrange
            DisabledException exception = new DisabledException("Conta desabilitada");

            // Act
            ResponseEntity<CustomErrorResponse> response =
                    exceptionHandler.handleDisabled(exception, request);

            // Assert
            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
            assertThat(response.getBody().getStatus()).isEqualTo(403);
            assertThat(response.getBody().getError()).isEqualTo("Conta desabilitada");
        }

        @Test
        @DisplayName("Deveria mapear UserNotVerifiedOrNotEnabledException para 403")
        void shouldMap_UserNotVerifiedOrNotEnabledException_To403() {
            // Arrange
            UserNotVerifiedOrNotEnabledException exception =
                    new UserNotVerifiedOrNotEnabledException("Email não verificado");

            // Act
            ResponseEntity<CustomErrorResponse> response =
                    exceptionHandler.handleUserNotVerifiedOrNotEnabledException(exception, request);

            // Assert
            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
            assertThat(response.getBody().getStatus()).isEqualTo(403);
        }

        @Test
        @DisplayName("Deveria mapear LoggedUserAndChangeEmailTokenMismatchException para 403")
        void shouldMap_LoggedUserAndChangeEmailTokenMismatchException_To403() {
            // Arrange
            LoggedUserAndChangeEmailTokenMismatchException exception =
                    new LoggedUserAndChangeEmailTokenMismatchException(
                            "Token não pertence ao usuário");

            // Act
            ResponseEntity<CustomErrorResponse> response = exceptionHandler
                    .handleLoggedUserAndChangeEmailTokenMismatchException(exception, request);

            // Assert
            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
            assertThat(response.getBody().getStatus()).isEqualTo(403);
        }
    }

    // ========================================================================
    // TESTS: Not Found exceptions (404)
    // ========================================================================

    @Nested
    @DisplayName("Exceções de não encontrado - 404 NOT FOUND")
    class NotFoundExceptionsTests {

        @Test
        @DisplayName("Deveria mapear UserNotFoundException para 404")
        void shouldMap_UserNotFoundException_To404() {
            // Arrange
            UsernameNotFoundException exception =
                    new UsernameNotFoundException("Usuário não encontrado");

            // Act
            ResponseEntity<CustomErrorResponse> response =
                    exceptionHandler.handleUserNotFound(exception, request);

            // Assert
            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.NOT_FOUND);
            assertThat(response.getBody().getStatus()).isEqualTo(404);
            assertThat(response.getBody().getError()).isEqualTo("Usuário não encontrado");
        }

        @Test
        @DisplayName("Deveria mapear TokenNotFoundException para 404")
        void shouldMap_TokenNotFoundException_To404() {
            // Arrange
            TokenNotFoundException exception = new TokenNotFoundException("Token não encontrado");

            // Act
            ResponseEntity<CustomErrorResponse> response =
                    exceptionHandler.handleTokenNotFoundException(exception, request);

            // Assert
            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.NOT_FOUND);
            assertThat(response.getBody().getStatus()).isEqualTo(404);
        }
    }

    // ========================================================================
    // TESTS: Conflict exceptions (409)
    // ========================================================================

    @Nested
    @DisplayName("Exceções de conflito - 409 CONFLICT")
    class ConflictExceptionsTests {

        @Test
        @DisplayName("Deveria mapear UserAlreadyExistsException para 409")
        void shouldMap_UserAlreadyExistsException_To409() {
            // Arrange
            UserAlreadyExistsException exception =
                    new UserAlreadyExistsException("Usuário já existe");

            // Act
            ResponseEntity<CustomErrorResponse> response =
                    exceptionHandler.handleUserAlreadyExists(exception, request);

            // Assert
            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.CONFLICT);
            assertThat(response.getBody().getStatus()).isEqualTo(409);
            assertThat(response.getBody().getError()).isEqualTo("Usuário já existe");
        }

        @Test
        @DisplayName("Deveria mapear EmailAlreadyTakenException para 409")
        void shouldMap_EmailAlreadyTakenException_To409() {
            // Arrange
            EmailAlreadyTakenException exception =
                    new EmailAlreadyTakenException("Email já está em uso");

            // Act
            ResponseEntity<CustomErrorResponse> response =
                    exceptionHandler.handleEmailAlreadyTakenException(exception, request);

            // Assert
            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.CONFLICT);
            assertThat(response.getBody().getStatus()).isEqualTo(409);
        }
    }

    // ========================================================================
    // TESTS: Gone exceptions (410)
    // ========================================================================

    @Nested
    @DisplayName("Exceções de expirado - 410 GONE")
    class GoneExceptionsTests {

        @Test
        @DisplayName("Deveria mapear ExpiredTokenException para 410 com retryAfter")
        void shouldMap_ExpiredTokenException_To410WithRetryAfter() {
            // Arrange
            ExpiredTokenException exception = new ExpiredTokenException("Token expirado");

            // Act
            ResponseEntity<CustomErrorResponse> response =
                    exceptionHandler.handleExpiredTokenException(exception, request);

            // Assert
            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.GONE);
            assertThat(response.getBody().getStatus()).isEqualTo(410);
            assertThat(response.getBody().getError()).isEqualTo("Token expirado");
        }
    }

    // ========================================================================
    // TESTS: Bad Request exceptions (400)
    // ========================================================================

    @Nested
    @DisplayName("Exceções de requisição inválida - 400 BAD REQUEST")
    class BadRequestExceptionsTests {

        @Test
        @DisplayName("Deveria mapear InvalidTokenTypeException para 400")
        void shouldMap_InvalidTokenTypeException_To400() {
            // Arrange
            InvalidTokenTypeException exception =
                    new InvalidTokenTypeException("Tipo de token inválido");

            // Act
            ResponseEntity<CustomErrorResponse> response =
                    exceptionHandler.handleInvalidTokenTypeException(exception, request);

            // Assert
            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
            assertThat(response.getBody().getStatus()).isEqualTo(400);
        }

        @Test
        @DisplayName("Deveria mapear WrongPasswordException para 401")
        void shouldMap_WrongPasswordException_To400() {
            // Arrange
            WrongPasswordException exception = new WrongPasswordException("Senha incorreta");

            // Act
            ResponseEntity<CustomErrorResponse> response =
                    exceptionHandler.handleWrongPasswordException(exception, request);

            // Assert
            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
            assertThat(response.getBody().getStatus()).isEqualTo(401);
        }

        @Test
        @DisplayName("Deveria mapear DisabledException para 403")
        void shouldMap_DisabledException_To403() {
            // Arrange
            DisabledException exception = new DisabledException("Conta desativada");

            // Act
            ResponseEntity<CustomErrorResponse> response =
                    exceptionHandler.handleDisabled(exception, request);

            // Assert
            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
            assertThat(response.getBody().getStatus()).isEqualTo(403);
        }

        @Test
        @DisplayName("Deveria mapear MethodArgumentNotValidException para 400 com erros de validação")
        void shouldMap_MethodArgumentNotValidException_To400WithValidationErrors() {
            // Arrange
            BindingResult bindingResult = mock(BindingResult.class);
            MethodArgumentNotValidException exception =
                    new MethodArgumentNotValidException(null, bindingResult);

            FieldError error1 = new FieldError("user", "username", "Username é obrigatório");
            FieldError error2 = new FieldError("user", "email", "Email inválido");

            when(bindingResult.getAllErrors()).thenReturn(List.of(error1, error2));

            // Act
            ResponseEntity<CustomErrorResponse> response =
                    exceptionHandler.handleValidationExceptions(exception, request);

            // Assert
            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
            assertThat(response.getBody().getStatus()).isEqualTo(400);

            assertThat(response.getBody().getErrors()).isNotNull();
            assertThat(response.getBody().getErrors()).containsKey("username");
            assertThat(response.getBody().getErrors()).containsKey("email");
            assertThat(response.getBody().getErrors().get("username"))
                    .contains("Username é obrigatório");
            assertThat(response.getBody().getErrors().get("email")).contains("Email inválido");
        }
    }

    // ========================================================================
    // TESTS: Response structure
    // ========================================================================

    @Nested
    @DisplayName("Estrutura da resposta")
    class ResponseStructureTests {

        @Test
        @DisplayName("Deveria incluir timestamp na resposta")
        void shouldIncludeTimestamp_InResponse() {
            // Arrange
            UsernameNotFoundException exception = new UsernameNotFoundException("Teste");
            Instant before = Instant.now();

            // Act
            ResponseEntity<CustomErrorResponse> response =
                    exceptionHandler.handleUserNotFound(exception, request);

            Instant after = Instant.now();

            // Assert
            assertThat(response.getBody().getTimestamp()).isAfterOrEqualTo(before)
                    .isBeforeOrEqualTo(after);
        }

        @Test
        @DisplayName("Deveria incluir status code na resposta")
        void shouldIncludeStatusCode_InResponse() {
            // Arrange
            UsernameNotFoundException exception = new UsernameNotFoundException("Teste");

            // Act
            ResponseEntity<CustomErrorResponse> response =
                    exceptionHandler.handleUserNotFound(exception, request);

            // Assert
            assertThat(response.getBody().getStatus()).isEqualTo(404);
        }

        @Test
        @DisplayName("Deveria incluir mensagem de erro na resposta")
        void shouldIncludeErrorMessage_InResponse() {
            // Arrange
            String errorMessage = "Mensagem de erro customizada";
            UsernameNotFoundException exception = new UsernameNotFoundException(errorMessage);

            // Act
            ResponseEntity<CustomErrorResponse> response =
                    exceptionHandler.handleUserNotFound(exception, request);

            // Assert
            assertThat(response.getBody().getError()).isEqualTo(errorMessage);
        }

        @Test
        @DisplayName("Deveria incluir path da requisição na resposta")
        void shouldIncludeRequestPath_InResponse() {
            // Arrange
            UsernameNotFoundException exception = new UsernameNotFoundException("Teste");

            // Act
            ResponseEntity<CustomErrorResponse> response =
                    exceptionHandler.handleUserNotFound(exception, request);

            // Assert
            assertThat(response.getBody().getPath()).isEqualTo(REQUEST_URI);
        }
    }

    // ========================================================================
    // TESTS: Edge cases
    // ========================================================================

    @Nested
    @DisplayName("Casos extremos")
    class EdgeCasesTests {

        @Test
        @DisplayName("Deveria lidar com mensagem de exceção null")
        void shouldHandle_NullExceptionMessage() {
            // Arrange
            UsernameNotFoundException exception = new UsernameNotFoundException(null);

            // Act
            ResponseEntity<CustomErrorResponse> response =
                    exceptionHandler.handleUserNotFound(exception, request);

            // Assert
            assertThat(response.getBody()).isNotNull();
            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.NOT_FOUND);
        }

        @Test
        @DisplayName("Deveria lidar com mensagem de exceção vazia")
        void shouldHandle_EmptyExceptionMessage() {
            // Arrange
            UsernameNotFoundException exception = new UsernameNotFoundException("");

            // Act
            ResponseEntity<CustomErrorResponse> response =
                    exceptionHandler.handleUserNotFound(exception, request);

            // Assert
            assertThat(response.getBody()).isNotNull();
            assertThat(response.getBody().getError()).isEmpty();
        }

        @Test
        @DisplayName("Deveria lidar com MethodArgumentNotValidException sem erros")
        void shouldHandle_MethodArgumentNotValidExceptionWithoutErrors() {
            // Arrange
            BindingResult bindingResult = mock(BindingResult.class);
            when(bindingResult.getFieldErrors()).thenReturn(List.of());

            MethodArgumentNotValidException exception =
                    new MethodArgumentNotValidException(null, bindingResult);

            // Act
            ResponseEntity<CustomErrorResponse> response =
                    exceptionHandler.handleValidationExceptions(exception, request);

            // Assert
            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
            assertThat(response.getBody()).isNotNull();
        }
    }
}
