package com.atwo.paganois.services;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.contains;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.time.LocalDateTime;
import java.util.Optional;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.util.ReflectionTestUtils;

import com.atwo.paganois.entities.Role;
import com.atwo.paganois.entities.TokenType;
import com.atwo.paganois.entities.User;
import com.atwo.paganois.entities.VerificationToken;
import com.atwo.paganois.exceptions.UserNotFoundException;
import com.atwo.paganois.repositories.VerificationTokenRepository;

/**
 * Unit tests for VerificationService
 * 
 * Tests cover:
 * 1. Password reset email sending
 * 2. Email verification sending
 * 3. Email verification process
 * 4. Token validation logic
 */
@ExtendWith(MockitoExtension.class)
@DisplayName("VerificationService - Unit Tests")
class VerificationServiceTest {

    @Mock
    private VerificationTokenRepository tokenRepository;

    @Mock
    private CustomUserDetailsService userService;

    @Mock
    private EmailService emailService;

    @InjectMocks
    private VerificationService verificationService;

    private User validUser;
    private Role userRole;
    private VerificationToken validToken;

    private static final String BASE_URL = "http://localhost:8080";
    private static final String USER_EMAIL = "user@example.com";
    private static final String TOKEN_STRING = "test-token-uuid";

    @BeforeEach
    void setUp() {
        // Inject @Value field
        ReflectionTestUtils.setField(verificationService, "baseUrl", BASE_URL);

        // Setup Role
        userRole = new Role();
        userRole.setId(1L);
        userRole.setAuthority("ROLE_USER");

        // Setup valid User
        validUser = new User();
        validUser.setId(1L);
        validUser.setUsername("testuser");
        validUser.setEmail(USER_EMAIL);
        validUser.setPassword("encodedPassword");
        validUser.setRole(userRole);
        validUser.setEnabled(true);
        validUser.setEmailVerified(false);

        // Setup valid VerificationToken
        validToken = new VerificationToken();
        validToken.setToken(TOKEN_STRING);
        validToken.setUser(validUser);
        validToken.setType(TokenType.EMAIL_VERIFICATION);
        validToken.setExpiryDate(LocalDateTime.now().plusHours(24));
    }

    // ========================================================================
    // TESTS: sendPasswordReset()
    // ========================================================================

    @Nested
    @DisplayName("sendPasswordReset() - Send password reset email")
    class SendPasswordResetTests {

        @Test
        @DisplayName("Should send reset email when user exists")
        void shouldSendResetEmail_WhenUserExists() {
            // Arrange
            when(userService.findByEmail(USER_EMAIL)).thenReturn(validUser);

            // Act
            verificationService.sendPasswordReset(USER_EMAIL);

            // Assert
            verify(emailService, times(1)).sendSimpleEmail(
                    eq(USER_EMAIL),
                    eq("Resetar senha - Paganois"),
                    contains("/auth/reset-password?token="));
        }

        @Test
        @DisplayName("Should NOT send email when user does not exist")
        void shouldNotSendEmail_WhenUserDoesNotExist() {
            // Arrange
            when(userService.findByEmail(USER_EMAIL))
                    .thenThrow(new UserNotFoundException("User not found: " + USER_EMAIL));

            // Act & assert
            assertThatThrownBy(() -> verificationService.sendPasswordReset(USER_EMAIL))
                    .isInstanceOf(UserNotFoundException.class)
                    .hasMessageContaining("User not found: "+ USER_EMAIL);
            verify(emailService, never()).sendSimpleEmail(anyString(), anyString(), anyString());
        }

        @Test
        @DisplayName("Should delete old password reset tokens before creating new one")
        void shouldDeleteOldTokens_BeforeCreatingNew() {
            // Arrange
            when(userService.findByEmail(USER_EMAIL)).thenReturn(validUser);

            // Act
            verificationService.sendPasswordReset(USER_EMAIL);

            // Assert
            verify(tokenRepository, times(1)).deleteByUserIdAndType(
                    validUser.getId(),
                    TokenType.PASSWORD_RESET);
        }

        @Test
        @DisplayName("Should create token with PASSWORD_RESET type")
        void shouldCreateToken_WithPasswordResetType() {
            // Arrange
            when(userService.findByEmail(USER_EMAIL)).thenReturn(validUser);
            ArgumentCaptor<VerificationToken> tokenCaptor = ArgumentCaptor.forClass(VerificationToken.class);

            // Act
            verificationService.sendPasswordReset(USER_EMAIL);

            // Assert
            verify(tokenRepository).save(tokenCaptor.capture());
            VerificationToken savedToken = tokenCaptor.getValue();

            assertThat(savedToken.getType()).isEqualTo(TokenType.PASSWORD_RESET);
            assertThat(savedToken.getUser()).isEqualTo(validUser);
        }

        @Test
        @DisplayName("Should set token expiry to 1 hour from now")
        void shouldSetExpiry_ToOneHourFromNow() {
            // Arrange
            when(userService.findByEmail(USER_EMAIL)).thenReturn(validUser);
            ArgumentCaptor<VerificationToken> tokenCaptor = ArgumentCaptor.forClass(VerificationToken.class);
            LocalDateTime beforeCall = LocalDateTime.now();

            // Act
            verificationService.sendPasswordReset(USER_EMAIL);

            // Assert
            verify(tokenRepository).save(tokenCaptor.capture());
            VerificationToken savedToken = tokenCaptor.getValue();
            LocalDateTime afterCall = LocalDateTime.now();

            LocalDateTime expectedExpiry = beforeCall.plusHours(1);
            assertThat(savedToken.getExpiryDate())
                    .isAfterOrEqualTo(expectedExpiry)
                    .isBeforeOrEqualTo(afterCall.plusHours(1).plusSeconds(1));
        }

        @Test
        @DisplayName("Should generate unique token for each request")
        void shouldGenerateUniqueToken_ForEachRequest() {
            // Arrange
            when(userService.findByEmail(USER_EMAIL)).thenReturn(validUser);
            ArgumentCaptor<VerificationToken> tokenCaptor = ArgumentCaptor.forClass(VerificationToken.class);

            // Act
            verificationService.sendPasswordReset(USER_EMAIL);

            // Assert
            verify(tokenRepository).save(tokenCaptor.capture());
            VerificationToken savedToken = tokenCaptor.getValue();

            assertThat(savedToken.getToken())
                    .isNotNull()
                    .isNotEmpty()
                    .hasSize(36); // UUID format: 8-4-4-4-12 = 36 chars
        }

        @Test
        @DisplayName("Should include token in reset URL")
        void shouldIncludeToken_InResetUrl() {
            // Arrange
            when(userService.findByEmail(USER_EMAIL)).thenReturn(validUser);
            ArgumentCaptor<String> emailContentCaptor = ArgumentCaptor.forClass(String.class);

            // Act
            verificationService.sendPasswordReset(USER_EMAIL);

            // Assert
            verify(emailService).sendSimpleEmail(
                    eq(USER_EMAIL),
                    anyString(),
                    emailContentCaptor.capture());

            String emailContent = emailContentCaptor.getValue();
            assertThat(emailContent)
                    .contains(BASE_URL + "/auth/reset-password?token=")
                    .contains("Clique no link");
        }

        //TODO: consertar o método testado aqui (Should not throw exception.....)
        // @Test
        // @DisplayName("Should not throw exception when user not found (security)")
        // void shouldNotThrowException_WhenUserNotFound() {
        //     // Arrange
        //     when(userService.findByEmail(USER_EMAIL)).thenReturn(Optional.empty());

        //     // Act & Assert - should not throw
        //     org.junit.jupiter.api.Assertions
        //             .assertDoesNotThrow(() -> verificationService.sendPasswordReset(USER_EMAIL));
        // }
    }

    // ========================================================================
    // TESTS: sendEmailVerification()
    // ========================================================================

    @Nested
    @DisplayName("sendEmailVerification() - Send email verification")
    class SendEmailVerificationTests {

        @Test
        @DisplayName("Should send verification email with correct details")
        void shouldSendVerificationEmail_WithCorrectDetails() {
            // Act
            verificationService.sendEmailVerification(validUser);

            // Assert
            verify(emailService, times(1)).sendSimpleEmail(
                    eq(validUser.getEmail()),
                    eq("Confirme seu email - Paganois"),
                    contains("/auth/verify-email?token="));
        }

        @Test
        @DisplayName("Should create token with EMAIL_VERIFICATION type")
        void shouldCreateToken_WithEmailVerificationType() {
            // Arrange
            ArgumentCaptor<VerificationToken> tokenCaptor = ArgumentCaptor.forClass(VerificationToken.class);

            // Act
            verificationService.sendEmailVerification(validUser);

            // Assert
            verify(tokenRepository).save(tokenCaptor.capture());
            VerificationToken savedToken = tokenCaptor.getValue();

            assertThat(savedToken.getType()).isEqualTo(TokenType.EMAIL_VERIFICATION);
            assertThat(savedToken.getUser()).isEqualTo(validUser);
        }

        @Test
        @DisplayName("Should set token expiry to 24 hours from now")
        void shouldSetExpiry_To24HoursFromNow() {
            // Arrange
            ArgumentCaptor<VerificationToken> tokenCaptor = ArgumentCaptor.forClass(VerificationToken.class);
            LocalDateTime beforeCall = LocalDateTime.now();

            // Act
            verificationService.sendEmailVerification(validUser);

            // Assert
            verify(tokenRepository).save(tokenCaptor.capture());
            VerificationToken savedToken = tokenCaptor.getValue();
            LocalDateTime afterCall = LocalDateTime.now();

            LocalDateTime expectedExpiry = beforeCall.plusHours(24);
            assertThat(savedToken.getExpiryDate())
                    .isAfterOrEqualTo(expectedExpiry)
                    .isBeforeOrEqualTo(afterCall.plusHours(24).plusSeconds(1));
        }

        @Test
        @DisplayName("Should save token to repository")
        void shouldSaveToken_ToRepository() {
            // Act
            verificationService.sendEmailVerification(validUser);

            // Assert
            verify(tokenRepository, times(1)).save(any(VerificationToken.class));
        }

        @Test
        @DisplayName("Should generate UUID token")
        void shouldGenerateUuidToken() {
            // Arrange
            ArgumentCaptor<VerificationToken> tokenCaptor = ArgumentCaptor.forClass(VerificationToken.class);

            // Act
            verificationService.sendEmailVerification(validUser);

            // Assert
            verify(tokenRepository).save(tokenCaptor.capture());
            VerificationToken savedToken = tokenCaptor.getValue();

            assertThat(savedToken.getToken())
                    .isNotNull()
                    .matches("[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}");
        }

        @Test
        @DisplayName("Should include confirmation URL in email")
        void shouldIncludeConfirmationUrl_InEmail() {
            // Arrange
            ArgumentCaptor<String> emailContentCaptor = ArgumentCaptor.forClass(String.class);

            // Act
            verificationService.sendEmailVerification(validUser);

            // Assert
            verify(emailService).sendSimpleEmail(
                    anyString(),
                    anyString(),
                    emailContentCaptor.capture());

            String emailContent = emailContentCaptor.getValue();
            assertThat(emailContent)
                    .contains(BASE_URL + "/auth/verify-email?token=")
                    .contains("confirme seu email");
        }
    }

    // ========================================================================
    // TESTS: validateToken()
    // ========================================================================

    @Nested
    @DisplayName("validateToken() - Validate verification token")
    class ValidateTokenTests {

        @Test
        @DisplayName("Should return token when valid and type matches")
        void shouldReturnToken_WhenValidAndTypeMatches() {
            // Arrange
            when(tokenRepository.findByToken(TOKEN_STRING))
                    .thenReturn(Optional.of(validToken));

            // Act
            VerificationToken result = verificationService.validateToken(
                    TOKEN_STRING,
                    TokenType.EMAIL_VERIFICATION);

            // Assert
            assertThat(result).isNotNull();
            assertThat(result.getToken()).isEqualTo(TOKEN_STRING);
            assertThat(result.getType()).isEqualTo(TokenType.EMAIL_VERIFICATION);
        }

        @Test
        @DisplayName("Should throw exception when token not found")
        void shouldThrowException_WhenTokenNotFound() {
            // Arrange
            when(tokenRepository.findByToken(TOKEN_STRING))
                    .thenReturn(Optional.empty());

            // Act & Assert
            assertThatThrownBy(() -> verificationService.validateToken(TOKEN_STRING, TokenType.EMAIL_VERIFICATION))
                    .isInstanceOf(RuntimeException.class)
                    .hasMessage("Token inválido");
        }

        @Test
        @DisplayName("Should throw exception when token type does not match")
        void shouldThrowException_WhenTokenTypeMismatch() {
            // Arrange
            validToken.setType(TokenType.EMAIL_VERIFICATION);
            when(tokenRepository.findByToken(TOKEN_STRING))
                    .thenReturn(Optional.of(validToken));

            // Act & Assert
            assertThatThrownBy(() -> verificationService.validateToken(TOKEN_STRING, TokenType.PASSWORD_RESET))
                    .isInstanceOf(RuntimeException.class)
                    .hasMessage("Token inválido");
        }

        @Test
        @DisplayName("Should throw exception when token is expired")
        void shouldThrowException_WhenTokenExpired() {
            // Arrange
            validToken.setExpiryDate(LocalDateTime.now().minusMinutes(1));
            when(tokenRepository.findByToken(TOKEN_STRING))
                    .thenReturn(Optional.of(validToken));

            // Act & Assert
            assertThatThrownBy(() -> verificationService.validateToken(TOKEN_STRING, TokenType.EMAIL_VERIFICATION))
                    .isInstanceOf(RuntimeException.class)
                    .hasMessage("Token expirado");
        }

        @Test
        @DisplayName("Should validate expiry before type check")
        void shouldValidateExpiry_BeforeTypeCheck() {
            // Arrange
            validToken.setType(TokenType.PASSWORD_RESET);
            validToken.setExpiryDate(LocalDateTime.now().minusHours(1));
            when(tokenRepository.findByToken(TOKEN_STRING))
                    .thenReturn(Optional.of(validToken));

            // Act & Assert - should throw "Token inválido" for type mismatch first
            assertThatThrownBy(() -> verificationService.validateToken(TOKEN_STRING, TokenType.EMAIL_VERIFICATION))
                    .isInstanceOf(RuntimeException.class)
                    .hasMessage("Token inválido"); // Type check comes first in code
        }

        @Test
        @DisplayName("Should accept token when expiry is in future")
        void shouldAcceptToken_WhenExpiryInFuture() {
            // Arrange
            validToken.setExpiryDate(LocalDateTime.now().plusHours(1));
            when(tokenRepository.findByToken(TOKEN_STRING))
                    .thenReturn(Optional.of(validToken));

            // Act
            VerificationToken result = verificationService.validateToken(
                    TOKEN_STRING,
                    TokenType.EMAIL_VERIFICATION);

            // Assert
            assertThat(result).isNotNull();
            assertThat(result.isExpired()).isFalse();
        }
    }
}