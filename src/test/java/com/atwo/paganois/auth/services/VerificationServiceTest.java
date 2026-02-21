package com.atwo.paganois.auth.services;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
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
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.util.ReflectionTestUtils;
import com.atwo.paganois.auth.entities.TokenType;
import com.atwo.paganois.auth.entities.VerificationToken;
import com.atwo.paganois.auth.exceptions.ExpiredTokenException;
import com.atwo.paganois.auth.exceptions.InvalidTokenTypeException;
import com.atwo.paganois.auth.exceptions.TokenNotFoundException;
import com.atwo.paganois.auth.repositories.VerificationTokenRepository;
import com.atwo.paganois.email.services.EmailService;
import com.atwo.paganois.user.entities.Role;
import com.atwo.paganois.user.entities.User;

/**
 * Unit tests for VerificationService
 * 
 * Structure: - sendPasswordReset() - Password reset email sending - sendEmailVerification() - Email
 * verification sending - sendEmailChangeVerification() - Email change verification -
 * validateToken() - Token validation logic - deleteToken() - Delete single token -
 * deleteByUserIdAndType() - Delete tokens by user and type
 */
@ExtendWith(MockitoExtension.class)
@DisplayName("VerificationService - Unit Tests")
class VerificationServiceTest {

    @Mock
    private VerificationTokenRepository tokenRepository;

    @Mock
    private EmailService emailService;

    private VerificationService verificationService;

    private User validUser;
    private Role userRole;

    private static final String BASE_URL = "http://localhost:8080";
    private static final String EMAIL = "user@example.com";
    private static final String NEW_EMAIL = "new@example.com";
    private static final String TOKEN_STRING = "test-token-uuid";

    @BeforeEach
    void setUp() {
        verificationService = new VerificationService();
        ReflectionTestUtils.setField(verificationService, "tokenRepository", tokenRepository);
        ReflectionTestUtils.setField(verificationService, "emailService", emailService);
        ReflectionTestUtils.setField(verificationService, "baseUrl", BASE_URL);

        userRole = new Role();
        userRole.setId(1L);
        userRole.setAuthority("ROLE_USER");

        validUser = new User();
        validUser.setId(1L);
        validUser.setUsername("testuser");
        validUser.setEmail(EMAIL);
        validUser.setPassword("encodedPassword");
        validUser.setRole(userRole);
        validUser.setEnabled(true);
        validUser.setEmailVerified(false);
    }

    // ========================================================================
    // TESTS: sendPasswordReset()
    // ========================================================================

    @Nested
    @DisplayName("sendPasswordReset() - Enviar email de reset de senha")
    class SendPasswordResetTests {

        @Test
        @DisplayName("Deveria deletar tokens antigos de reset de senha antes de criar novo")
        void shouldDeleteOldTokens_BeforeCreatingNew() {
            // Arrange
            when(tokenRepository.save(any(VerificationToken.class)))
                    .thenReturn(new VerificationToken());

            // Act
            verificationService.sendPasswordReset(validUser);

            // Assert
            verify(tokenRepository).deleteByUserIdAndType(validUser.getId(),
                    TokenType.PASSWORD_RESET);
        }

        @Test
        @DisplayName("Deveria criar token com tipo PASSWORD_RESET")
        void shouldCreateToken_WithPasswordResetType() {
            // Arrange
            ArgumentCaptor<VerificationToken> captor =
                    ArgumentCaptor.forClass(VerificationToken.class);
            when(tokenRepository.save(any(VerificationToken.class)))
                    .thenReturn(new VerificationToken());

            // Act
            verificationService.sendPasswordReset(validUser);

            // Assert
            verify(tokenRepository).save(captor.capture());
            VerificationToken savedToken = captor.getValue();

            assertThat(savedToken.getType()).isEqualTo(TokenType.PASSWORD_RESET);
            assertThat(savedToken.getUser()).isEqualTo(validUser);
        }

        @Test
        @DisplayName("Deveria definir expiração do token para 1 hora a partir de agora")
        void shouldSetExpiry_ToOneHourFromNow() {
            // Arrange
            ArgumentCaptor<VerificationToken> captor =
                    ArgumentCaptor.forClass(VerificationToken.class);
            LocalDateTime beforeCall = LocalDateTime.now();
            when(tokenRepository.save(any(VerificationToken.class)))
                    .thenReturn(new VerificationToken());

            // Act
            verificationService.sendPasswordReset(validUser);

            // Assert
            verify(tokenRepository).save(captor.capture());
            VerificationToken savedToken = captor.getValue();
            LocalDateTime afterCall = LocalDateTime.now();

            assertThat(savedToken.getExpiryDate()).isAfter(beforeCall.plusMinutes(59))
                    .isBefore(afterCall.plusHours(1).plusSeconds(1));
        }

        @Test
        @DisplayName("Deveria gerar token único (UUID)")
        void shouldGenerateUniqueToken() {
            // Arrange
            ArgumentCaptor<VerificationToken> captor =
                    ArgumentCaptor.forClass(VerificationToken.class);
            when(tokenRepository.save(any(VerificationToken.class)))
                    .thenReturn(new VerificationToken());

            // Act
            verificationService.sendPasswordReset(validUser);

            // Assert
            verify(tokenRepository).save(captor.capture());
            VerificationToken savedToken = captor.getValue();

            assertThat(savedToken.getToken()).isNotNull().isNotEmpty().hasSize(36); // UUID format
        }

        @Test
        @DisplayName("Deveria enviar email com token")
        void shouldSendEmail_WithToken() {
            // Arrange
            when(tokenRepository.save(any(VerificationToken.class)))
                    .thenReturn(new VerificationToken());
            ArgumentCaptor<String> contentCaptor = ArgumentCaptor.forClass(String.class);

            // Act
            verificationService.sendPasswordReset(validUser);

            // Assert
            verify(emailService).sendSimpleEmail(eq(EMAIL), eq("Resetar senha - Paganois"),
                    contentCaptor.capture());

            String emailContent = contentCaptor.getValue();
            assertThat(emailContent).contains("Utilize esse token para resetar sua senha:");
        }
    }

    // ========================================================================
    // TESTS: sendEmailVerification()
    // ========================================================================

    @Nested
    @DisplayName("sendEmailVerification() - Enviar email de verificação")
    class SendEmailVerificationTests {

        @Test
        @DisplayName("Deveria deletar tokens antigos de verificação antes de criar novo")
        void shouldDeleteOldTokens_BeforeCreatingNew() {
            // Arrange
            when(tokenRepository.save(any(VerificationToken.class)))
                    .thenReturn(new VerificationToken());

            // Act
            verificationService.sendEmailVerification(validUser);

            // Assert
            verify(tokenRepository).deleteByUserIdAndType(validUser.getId(),
                    TokenType.EMAIL_VERIFICATION);
        }

        @Test
        @DisplayName("Deveria criar token com tipo EMAIL_VERIFICATION")
        void shouldCreateToken_WithEmailVerificationType() {
            // Arrange
            ArgumentCaptor<VerificationToken> captor =
                    ArgumentCaptor.forClass(VerificationToken.class);
            when(tokenRepository.save(any(VerificationToken.class)))
                    .thenReturn(new VerificationToken());

            // Act
            verificationService.sendEmailVerification(validUser);

            // Assert
            verify(tokenRepository).save(captor.capture());
            VerificationToken savedToken = captor.getValue();

            assertThat(savedToken.getType()).isEqualTo(TokenType.EMAIL_VERIFICATION);
            assertThat(savedToken.getUser()).isEqualTo(validUser);
        }

        @Test
        @DisplayName("Deveria definir expiração do token para 24 horas a partir de agora")
        void shouldSetExpiry_To24HoursFromNow() {
            // Arrange
            ArgumentCaptor<VerificationToken> captor =
                    ArgumentCaptor.forClass(VerificationToken.class);
            LocalDateTime beforeCall = LocalDateTime.now();
            when(tokenRepository.save(any(VerificationToken.class)))
                    .thenReturn(new VerificationToken());

            // Act
            verificationService.sendEmailVerification(validUser);

            // Assert
            verify(tokenRepository).save(captor.capture());
            VerificationToken savedToken = captor.getValue();
            LocalDateTime afterCall = LocalDateTime.now();

            assertThat(savedToken.getExpiryDate()).isAfter(beforeCall.plusHours(23).plusMinutes(59))
                    .isBefore(afterCall.plusHours(24).plusSeconds(1));
        }

        @Test
        @DisplayName("Deveria enviar email com URL de confirmação")
        void shouldSendEmail_WithConfirmationUrl() {
            // Arrange
            when(tokenRepository.save(any(VerificationToken.class)))
                    .thenReturn(new VerificationToken());
            ArgumentCaptor<String> contentCaptor = ArgumentCaptor.forClass(String.class);

            // Act
            verificationService.sendEmailVerification(validUser);

            // Assert
            verify(emailService).sendSimpleEmail(eq(EMAIL), eq("Confirme seu email - Paganois"),
                    contentCaptor.capture());

            String emailContent = contentCaptor.getValue();
            assertThat(emailContent).contains(BASE_URL + "/auth/verify-email?token=")
                    .contains("Por favor, confirme seu email clicando no link:");
        }
    }

    // ========================================================================
    // TESTS: sendEmailChangeVerification()
    // ========================================================================

    @Nested
    @DisplayName("sendEmailChangeVerification() - Enviar verificação de mudança de email")
    class SendEmailChangeVerificationTests {

        @Test
        @DisplayName("Deveria deletar tokens antigos de mudança de email antes de criar novo")
        void shouldDeleteOldTokens_BeforeCreatingNew() {
            // Arrange
            when(tokenRepository.save(any(VerificationToken.class)))
                    .thenReturn(new VerificationToken());

            // Act
            verificationService.sendEmailChangeVerification(validUser, NEW_EMAIL);

            // Assert
            verify(tokenRepository).deleteByUserIdAndType(validUser.getId(),
                    TokenType.EMAIL_CHANGE);
        }

        @Test
        @DisplayName("Deveria criar token com tipo EMAIL_CHANGE e email pendente")
        void shouldCreateToken_WithEmailChangeTypeAndPendingEmail() {
            // Arrange
            ArgumentCaptor<VerificationToken> captor =
                    ArgumentCaptor.forClass(VerificationToken.class);
            when(tokenRepository.save(any(VerificationToken.class)))
                    .thenReturn(new VerificationToken());

            // Act
            verificationService.sendEmailChangeVerification(validUser, NEW_EMAIL);

            // Assert
            verify(tokenRepository).save(captor.capture());
            VerificationToken savedToken = captor.getValue();

            assertThat(savedToken.getType()).isEqualTo(TokenType.EMAIL_CHANGE);
            assertThat(savedToken.getUser()).isEqualTo(validUser);
            assertThat(savedToken.getPendingEmail()).isEqualTo(NEW_EMAIL);
        }

        @Test
        @DisplayName("Deveria definir expiração do token para 24 horas")
        void shouldSetExpiry_To24Hours() {
            // Arrange
            ArgumentCaptor<VerificationToken> captor =
                    ArgumentCaptor.forClass(VerificationToken.class);
            LocalDateTime beforeCall = LocalDateTime.now();
            when(tokenRepository.save(any(VerificationToken.class)))
                    .thenReturn(new VerificationToken());

            // Act
            verificationService.sendEmailChangeVerification(validUser, NEW_EMAIL);

            // Assert
            verify(tokenRepository).save(captor.capture());
            VerificationToken savedToken = captor.getValue();
            LocalDateTime afterCall = LocalDateTime.now();

            assertThat(savedToken.getExpiryDate()).isAfter(beforeCall.plusHours(23).plusMinutes(59))
                    .isBefore(afterCall.plusHours(24).plusSeconds(1));
        }

        @Test
        @DisplayName("Deveria enviar email para o NOVO endereço com informações de mudança")
        void shouldSendEmail_ToNewAddressWithChangeInfo() {
            // Arrange
            when(tokenRepository.save(any(VerificationToken.class)))
                    .thenReturn(new VerificationToken());
            ArgumentCaptor<String> emailCaptor = ArgumentCaptor.forClass(String.class);
            ArgumentCaptor<String> contentCaptor = ArgumentCaptor.forClass(String.class);

            // Act
            verificationService.sendEmailChangeVerification(validUser, NEW_EMAIL);

            // Assert
            verify(emailService).sendSimpleEmail(emailCaptor.capture(),
                    eq("Confirme mudança de email - Paganois"), contentCaptor.capture());

            assertThat(emailCaptor.getValue()).isEqualTo(NEW_EMAIL);

            String emailContent = contentCaptor.getValue();
            assertThat(emailContent).contains("Email atual: " + EMAIL)
                    .contains("Novo email: " + NEW_EMAIL)
                    .contains(BASE_URL + "/api/users/me/email/confirm?token=")
                    .contains("Clique no link para confirmar:");
        }
    }

    // ========================================================================
    // TESTS: validateToken()
    // ========================================================================

    @Nested
    @DisplayName("validateToken() - Validar token")
    class ValidateTokenTests {

        private VerificationToken validToken;

        @BeforeEach
        void setUp() {
            validToken = new VerificationToken();
            validToken.setToken(TOKEN_STRING);
            validToken.setUser(validUser);
            validToken.setType(TokenType.EMAIL_VERIFICATION);
            validToken.setExpiryDate(LocalDateTime.now().plusHours(24));
        }

        @Test
        @DisplayName("Deveria retornar token quando token é válido")
        void shouldReturnToken_WhenTokenIsValid() {
            // Arrange
            when(tokenRepository.findByToken(TOKEN_STRING)).thenReturn(Optional.of(validToken));

            // Act
            VerificationToken result =
                    verificationService.validateToken(TOKEN_STRING, TokenType.EMAIL_VERIFICATION);

            // Assert
            assertThat(result).isNotNull().isEqualTo(validToken);
        }

        @Test
        @DisplayName("Deveria lançar TokenNotFoundException quando token não existe")
        void shouldThrowTokenNotFoundException_WhenTokenDoesNotExist() {
            // Arrange
            when(tokenRepository.findByToken(TOKEN_STRING)).thenReturn(Optional.empty());

            // Act & Assert
            assertThatThrownBy(() -> verificationService.validateToken(TOKEN_STRING,
                    TokenType.EMAIL_VERIFICATION)).isInstanceOf(TokenNotFoundException.class)
                            .hasMessage("Token não encontrado");
        }

        @Test
        @DisplayName("Deveria lançar InvalidTokenTypeException quando tipo de token está errado")
        void shouldThrowInvalidTokenTypeException_WhenTokenTypeIsWrong() {
            // Arrange
            validToken.setType(TokenType.PASSWORD_RESET);
            when(tokenRepository.findByToken(TOKEN_STRING)).thenReturn(Optional.of(validToken));

            // Act & Assert
            assertThatThrownBy(() -> verificationService.validateToken(TOKEN_STRING,
                    TokenType.EMAIL_VERIFICATION)).isInstanceOf(InvalidTokenTypeException.class)
                            .hasMessage("Token com tipo inválido");
        }

        @Test
        @DisplayName("Deveria lançar ExpiredTokenException quando token está expirado")
        void shouldThrowExpiredTokenException_WhenTokenIsExpired() {
            // Arrange
            validToken.setExpiryDate(LocalDateTime.now().minusHours(1));
            when(tokenRepository.findByToken(TOKEN_STRING)).thenReturn(Optional.of(validToken));

            // Act & Assert
            assertThatThrownBy(() -> verificationService.validateToken(TOKEN_STRING,
                    TokenType.EMAIL_VERIFICATION)).isInstanceOf(ExpiredTokenException.class)
                            .hasMessage("Token expirado");
        }

        @Test
        @DisplayName("Deveria validar tipo antes de validar expiração")
        void shouldValidateType_BeforeExpiration() {
            // Arrange - Token com tipo errado E expirado
            validToken.setType(TokenType.PASSWORD_RESET);
            validToken.setExpiryDate(LocalDateTime.now().minusHours(1));
            when(tokenRepository.findByToken(TOKEN_STRING)).thenReturn(Optional.of(validToken));

            // Act & Assert - Deve lançar exceção de tipo, não de expiração
            assertThatThrownBy(() -> verificationService.validateToken(TOKEN_STRING,
                    TokenType.EMAIL_VERIFICATION)).isInstanceOf(InvalidTokenTypeException.class)
                            .hasMessage("Token com tipo inválido");
        }

        @Test
        @DisplayName("Deveria aceitar token quando expiração está no futuro")
        void shouldAcceptToken_WhenExpiryIsInFuture() {
            // Arrange
            validToken.setExpiryDate(LocalDateTime.now().plusHours(1));
            when(tokenRepository.findByToken(TOKEN_STRING)).thenReturn(Optional.of(validToken));

            // Act
            VerificationToken result =
                    verificationService.validateToken(TOKEN_STRING, TokenType.EMAIL_VERIFICATION);

            // Assert
            assertThat(result).isNotNull();
            assertThat(result.isExpired()).isFalse();
        }
    }

    // ========================================================================
    // TESTS: deleteToken()
    // ========================================================================

    @Nested
    @DisplayName("deleteToken() - Deletar token individual")
    class DeleteTokenTests {

        @Test
        @DisplayName("Deveria deletar token do repositório")
        void shouldDeleteToken_FromRepository() {
            // Arrange
            VerificationToken token = new VerificationToken();
            token.setToken(TOKEN_STRING);

            // Act
            verificationService.deleteToken(token);

            // Assert
            verify(tokenRepository).delete(token);
        }
    }

    // ========================================================================
    // TESTS: deleteByUserIdAndType()
    // ========================================================================

    @Nested
    @DisplayName("deleteByUserIdAndType() - Deletar tokens por usuário e tipo")
    class DeleteByUserIdAndTypeTests {

        @Test
        @DisplayName("Deveria deletar tokens pelo ID do usuário e tipo")
        void shouldDeleteTokens_ByUserIdAndType() {
            // Arrange
            Long userId = 1L;
            TokenType tokenType = TokenType.EMAIL_VERIFICATION;

            // Act
            verificationService.deleteByUserIdAndType(userId, tokenType);

            // Assert
            verify(tokenRepository).deleteByUserIdAndType(userId, tokenType);
        }

        @Test
        @DisplayName("Deveria aceitar diferentes tipos de token")
        void shouldAccept_DifferentTokenTypes() {
            // Arrange
            Long userId = 1L;

            // Act - Testa com cada tipo de token
            verificationService.deleteByUserIdAndType(userId, TokenType.EMAIL_VERIFICATION);
            verificationService.deleteByUserIdAndType(userId, TokenType.PASSWORD_RESET);
            verificationService.deleteByUserIdAndType(userId, TokenType.EMAIL_CHANGE);

            // Assert
            verify(tokenRepository).deleteByUserIdAndType(userId, TokenType.EMAIL_VERIFICATION);
            verify(tokenRepository).deleteByUserIdAndType(userId, TokenType.PASSWORD_RESET);
            verify(tokenRepository).deleteByUserIdAndType(userId, TokenType.EMAIL_CHANGE);
        }
    }
}
