package com.atwo.paganois.auth.services;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import java.time.LocalDateTime;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InOrder;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import com.atwo.paganois.auth.dtos.LoginRequest;
import com.atwo.paganois.auth.dtos.LoginResponse;
import com.atwo.paganois.auth.dtos.RefreshRequest;
import com.atwo.paganois.auth.dtos.RegisterRequest;
import com.atwo.paganois.auth.dtos.RegisterResponse;
import com.atwo.paganois.auth.entities.TokenType;
import com.atwo.paganois.auth.entities.VerificationToken;
import com.atwo.paganois.security.JwtUtil;
import com.atwo.paganois.shared.exceptions.InvalidTokenException;
import com.atwo.paganois.shared.exceptions.UserAlreadyExistsException;
import com.atwo.paganois.shared.exceptions.UserNotVerifiedOrNotEnabledException;
import com.atwo.paganois.user.entities.Role;
import com.atwo.paganois.user.entities.User;
import com.atwo.paganois.user.services.UserService;

/**
 * Unit tests for AuthService
 * 
 * Structure: - login() - Authentication and JWT generation - refresh() - Token refresh flow -
 * register() - User registration - resendEmailVerification() - Resend verification email -
 * verifyEmail() - Email verification - sendPasswordResetEmail() - Password reset request -
 * resetPassword() - Password reset execution - logout() - Single device logout - logoutAllDevices()
 * - Global logout
 */
@ExtendWith(MockitoExtension.class)
@DisplayName("AuthService - Unit Tests")
class AuthServiceTest {

    @Mock
    private UserService userService;

    @Mock
    private VerificationService verificationService;

    @Mock
    private AuthenticationManager authenticationManager;

    @Mock
    private TokenRevocationService tokenRevocationService;

    @Mock
    private JwtUtil jwtUtil;

    @Mock
    private PasswordEncoder passwordEncoder;

    private AuthService authService;

    private User validUser;
    private Role userRole;

    private static final String USERNAME = "testuser";
    private static final String EMAIL = "test@example.com";
    private static final String PASSWORD = "password123";
    private static final String ENCODED_PASSWORD = "$2a$10$encodedPassword";
    private static final String ACCESS_TOKEN = "access.jwt.token";
    private static final String REFRESH_TOKEN = "refresh.jwt.token";
    private static final String NEW_ACCESS_TOKEN = "new.access.jwt.token";
    private static final String NEW_REFRESH_TOKEN = "new.refresh.jwt.token";
    private static final String TOKEN = "verification-token-uuid";
    private static final String NEW_PASSWORD = "newPassword456";

    @BeforeEach
    void setUp() {
        // Cria AuthService manualmente e injeta os mocks
        authService = new AuthService();
        org.springframework.test.util.ReflectionTestUtils.setField(authService, "userService",
                userService);
        org.springframework.test.util.ReflectionTestUtils.setField(authService,
                "verificationService", verificationService);
        org.springframework.test.util.ReflectionTestUtils.setField(authService,
                "authenticationManager", authenticationManager);
        org.springframework.test.util.ReflectionTestUtils.setField(authService,
                "tokenRevocationService", tokenRevocationService);
        org.springframework.test.util.ReflectionTestUtils.setField(authService, "jwtUtil", jwtUtil);
        org.springframework.test.util.ReflectionTestUtils.setField(authService, "passwordEncoder",
                passwordEncoder);

        userRole = new Role();
        userRole.setId(1L);
        userRole.setAuthority("ROLE_USER");

        validUser = new User();
        validUser.setId(1L);
        validUser.setUsername(USERNAME);
        validUser.setEmail(EMAIL);
        validUser.setPassword(ENCODED_PASSWORD);
        validUser.setRole(userRole);
        validUser.setEnabled(true);
        validUser.setEmailVerified(true);
    }

    // ========================================================================
    // TESTS: login()
    // ========================================================================

    @Nested
    @DisplayName("login() - Autenticar usuário e gerar tokens")
    class LoginTests {

        private LoginRequest loginRequest;
        private Authentication authentication;

        @BeforeEach
        void setUp() {
            loginRequest = new LoginRequest(USERNAME, PASSWORD);
            authentication = mock(Authentication.class);
            when(authentication.getPrincipal()).thenReturn(validUser);
        }

        @Test
        @DisplayName("Deveria autenticar usuário com credenciais corretas")
        void shouldAuthenticateUser_WithCorrectCredentials() {
            // Arrange
            when(authenticationManager.authenticate(any(UsernamePasswordAuthenticationToken.class)))
                    .thenReturn(authentication);
            when(jwtUtil.generateToken(validUser)).thenReturn(ACCESS_TOKEN);
            when(jwtUtil.generateRefreshToken(validUser)).thenReturn(REFRESH_TOKEN);

            // Act
            LoginResponse response = authService.login(loginRequest);

            // Assert
            verify(authenticationManager)
                    .authenticate(any(UsernamePasswordAuthenticationToken.class));
            assertThat(response).isNotNull();
        }

        @Test
        @DisplayName("Deveria gerar access token e refresh token")
        void shouldGenerateAccessTokenAndRefreshToken() {
            // Arrange
            when(authenticationManager.authenticate(any(UsernamePasswordAuthenticationToken.class)))
                    .thenReturn(authentication);
            when(jwtUtil.generateToken(validUser)).thenReturn(ACCESS_TOKEN);
            when(jwtUtil.generateRefreshToken(validUser)).thenReturn(REFRESH_TOKEN);

            // Act
            LoginResponse response = authService.login(loginRequest);

            // Assert
            assertThat(response.accessToken()).isEqualTo(ACCESS_TOKEN);
            assertThat(response.refreshToken()).isEqualTo(REFRESH_TOKEN);
            verify(jwtUtil).generateToken(validUser);
            verify(jwtUtil).generateRefreshToken(validUser);
        }

        @Test
        @DisplayName("Deveria lançar exceção quando email não está verificado")
        void shouldThrowException_WhenEmailNotVerified() {
            // Arrange
            validUser.setEmailVerified(false);
            when(authenticationManager.authenticate(any(UsernamePasswordAuthenticationToken.class)))
                    .thenReturn(authentication);

            // Act & Assert
            assertThatThrownBy(() -> authService.login(loginRequest))
                    .isInstanceOf(UserNotVerifiedOrNotEnabledException.class)
                    .hasMessage("Conta desabilitada ou não verificada");

            verify(jwtUtil, never()).generateToken(any());
            verify(jwtUtil, never()).generateRefreshToken(any());
        }

        @Test
        @DisplayName("Deveria lançar exceção quando usuário está desabilitado")
        void shouldThrowException_WhenUserIsDisabled() {
            // Arrange
            validUser.setEnabled(false);
            when(authenticationManager.authenticate(any(UsernamePasswordAuthenticationToken.class)))
                    .thenReturn(authentication);

            // Act & Assert
            assertThatThrownBy(() -> authService.login(loginRequest))
                    .isInstanceOf(UserNotVerifiedOrNotEnabledException.class)
                    .hasMessage("Conta desabilitada ou não verificada");
        }
    }

    // ========================================================================
    // TESTS: refresh()
    // ========================================================================

    @Nested
    @DisplayName("refresh() - Atualizar tokens")
    class RefreshTests {

        private RefreshRequest refreshRequest;

        @BeforeEach
        void setUp() {
            refreshRequest = new RefreshRequest(REFRESH_TOKEN);
        }

        @Test
        @DisplayName("Deveria gerar novos tokens quando refresh token é válido")
        void shouldGenerateNewTokens_WhenRefreshTokenIsValid() {
            // Arrange
            when(tokenRevocationService.isRevoked(REFRESH_TOKEN)).thenReturn(false);
            when(jwtUtil.validateTokenWithVersion(REFRESH_TOKEN)).thenReturn(true);
            when(jwtUtil.extractUsername(REFRESH_TOKEN)).thenReturn(USERNAME);
            when(userService.loadByUsername(USERNAME)).thenReturn(validUser);
            when(jwtUtil.generateToken(validUser)).thenReturn(NEW_ACCESS_TOKEN);
            when(jwtUtil.generateRefreshToken(validUser)).thenReturn(NEW_REFRESH_TOKEN);

            // Act
            LoginResponse response = authService.refresh(refreshRequest);

            // Assert
            assertThat(response.accessToken()).isEqualTo(NEW_ACCESS_TOKEN);
            assertThat(response.refreshToken()).isEqualTo(NEW_REFRESH_TOKEN);
        }

        @Test
        @DisplayName("Deveria revogar o refresh token antigo")
        void shouldRevokeOldRefreshToken() {
            // Arrange
            when(tokenRevocationService.isRevoked(REFRESH_TOKEN)).thenReturn(false);
            when(jwtUtil.validateTokenWithVersion(REFRESH_TOKEN)).thenReturn(true);
            when(jwtUtil.extractUsername(REFRESH_TOKEN)).thenReturn(USERNAME);
            when(userService.loadByUsername(USERNAME)).thenReturn(validUser);
            when(jwtUtil.generateToken(validUser)).thenReturn(NEW_ACCESS_TOKEN);
            when(jwtUtil.generateRefreshToken(validUser)).thenReturn(NEW_REFRESH_TOKEN);

            // Act
            authService.refresh(refreshRequest);

            // Assert
            verify(tokenRevocationService).revokeToken(REFRESH_TOKEN);
        }

        @Test
        @DisplayName("Deveria lançar exceção quando refresh token já foi revogado")
        void shouldThrowException_WhenRefreshTokenAlreadyRevoked() {
            // Arrange
            when(tokenRevocationService.isRevoked(REFRESH_TOKEN)).thenReturn(true);

            // Act & Assert
            assertThatThrownBy(() -> authService.refresh(refreshRequest))
                    .isInstanceOf(InvalidTokenException.class)
                    .hasMessage("Token já foi usado ou revogado");

            verify(jwtUtil, never()).generateToken(any());
        }

        @Test
        @DisplayName("Deveria lançar exceção quando refresh token está expirado")
        void shouldThrowException_WhenRefreshTokenExpired() {
            // Arrange
            when(tokenRevocationService.isRevoked(REFRESH_TOKEN)).thenReturn(false);
            when(jwtUtil.validateTokenWithVersion(REFRESH_TOKEN)).thenReturn(false);

            // Act & Assert
            assertThatThrownBy(() -> authService.refresh(refreshRequest))
                    .isInstanceOf(InvalidTokenException.class)
                    .hasMessage("Token inválido, expirado ou com versão desatualizada");
        }
    }

    // ========================================================================
    // TESTS: register()
    // ========================================================================

    @Nested
    @DisplayName("register() - Registrar novo usuário")
    class RegisterTests {

        private RegisterRequest registerRequest;

        @BeforeEach
        void setUp() {
            registerRequest = new RegisterRequest(USERNAME, PASSWORD, EMAIL);
        }

        @Test
        @DisplayName("Deveria registrar usuário com sucesso quando dados são válidos")
        void shouldRegisterUser_WhenDataIsValid() {
            // Arrange
            when(userService.existsByUsername(USERNAME)).thenReturn(false);
            when(userService.existsByEmailAndVerified(EMAIL)).thenReturn(false);
            when(passwordEncoder.encode(PASSWORD)).thenReturn(ENCODED_PASSWORD);
            when(userService.registerUser(USERNAME, ENCODED_PASSWORD, EMAIL)).thenReturn(validUser);

            // Act
            RegisterResponse response = authService.register(registerRequest);

            // Assert
            assertThat(response).isNotNull();
            assertThat(response.id()).isEqualTo(validUser.getId());
            assertThat(response.username()).isEqualTo(USERNAME);
            verify(userService).registerUser(USERNAME, ENCODED_PASSWORD, EMAIL);
        }

        @Test
        @DisplayName("Deveria deletar usuários não verificados com o mesmo email antes de registrar")
        void shouldDeleteUnverifiedUsers_BeforeRegistering() {
            // Arrange
            when(userService.existsByUsername(USERNAME)).thenReturn(false);
            when(userService.existsByEmailAndVerified(EMAIL)).thenReturn(false);
            when(passwordEncoder.encode(PASSWORD)).thenReturn(ENCODED_PASSWORD);
            when(userService.registerUser(USERNAME, ENCODED_PASSWORD, EMAIL)).thenReturn(validUser);

            // Act
            authService.register(registerRequest);

            // Assert
            verify(userService).deleteUnverifiedByEmail(EMAIL);
        }

        @Test
        @DisplayName("Deveria enviar email de verificação após registrar usuário")
        void shouldSendVerificationEmail_AfterRegistering() {
            // Arrange
            when(userService.existsByUsername(USERNAME)).thenReturn(false);
            when(userService.existsByEmailAndVerified(EMAIL)).thenReturn(false);
            when(passwordEncoder.encode(PASSWORD)).thenReturn(ENCODED_PASSWORD);
            when(userService.registerUser(USERNAME, ENCODED_PASSWORD, EMAIL)).thenReturn(validUser);

            // Act
            authService.register(registerRequest);

            // Assert
            InOrder inOrder = Mockito.inOrder(userService, verificationService);
            inOrder.verify(userService).registerUser(USERNAME, ENCODED_PASSWORD, EMAIL);
            inOrder.verify(verificationService).sendEmailVerification(validUser);
        }

        @Test
        @DisplayName("Deveria encodar senha antes de registrar")
        void shouldEncodePassword_BeforeRegistering() {
            // Arrange
            when(userService.existsByUsername(USERNAME)).thenReturn(false);
            when(userService.existsByEmailAndVerified(EMAIL)).thenReturn(false);
            when(passwordEncoder.encode(PASSWORD)).thenReturn(ENCODED_PASSWORD);
            when(userService.registerUser(USERNAME, ENCODED_PASSWORD, EMAIL)).thenReturn(validUser);

            // Act
            authService.register(registerRequest);

            // Assert
            verify(passwordEncoder).encode(PASSWORD);
            verify(userService).registerUser(eq(USERNAME), eq(ENCODED_PASSWORD), eq(EMAIL));
        }

        @Test
        @DisplayName("Deveria lançar exceção quando username já existe")
        void shouldThrowException_WhenUsernameAlreadyExists() {
            // Arrange
            when(userService.existsByUsername(USERNAME)).thenReturn(true);

            // Act & Assert
            assertThatThrownBy(() -> authService.register(registerRequest))
                    .isInstanceOf(UserAlreadyExistsException.class)
                    .hasMessage("Username ou email já está em uso");

            verify(userService, never()).registerUser(any(), any(), any());
        }

        @Test
        @DisplayName("Deveria lançar exceção quando email já está verificado")
        void shouldThrowException_WhenEmailAlreadyVerified() {
            // Arrange
            when(userService.existsByUsername(USERNAME)).thenReturn(false);
            when(userService.existsByEmailAndVerified(EMAIL)).thenReturn(true);

            // Act & Assert
            assertThatThrownBy(() -> authService.register(registerRequest))
                    .isInstanceOf(UserAlreadyExistsException.class)
                    .hasMessage("Username ou email já está em uso");

            verify(userService, never()).registerUser(any(), any(), any());
        }
    }

    // ========================================================================
    // TESTS: resendEmailVerification()
    // ========================================================================

    @Nested
    @DisplayName("resendEmailVerification() - Reenviar email de verificação")
    class ResendEmailVerificationTests {

        @Test
        @DisplayName("Deveria reenviar email quando usuário existe e não está verificado")
        void shouldResendEmail_WhenUserExistsAndNotVerified() {
            // Arrange
            validUser.setEmailVerified(false);
            when(userService.existsByEmail(EMAIL)).thenReturn(true);
            when(userService.findByEmail(EMAIL)).thenReturn(validUser);

            // Act
            authService.resendEmailVerification(EMAIL);

            // Assert
            verify(verificationService).sendEmailVerification(validUser);
        }

        @Test
        @DisplayName("Deveria não enviar email quando usuário não existe")
        void shouldNotSendEmail_WhenUserDoesNotExist() {
            // Arrange
            when(userService.existsByEmail(EMAIL)).thenReturn(false);

            // Act
            authService.resendEmailVerification(EMAIL);

            // Assert
            verify(verificationService, never()).sendEmailVerification(any());
        }

        @Test
        @DisplayName("Deveria não enviar email quando usuário já está verificado")
        void shouldNotSendEmail_WhenUserAlreadyVerified() {
            // Arrange
            when(userService.existsByEmail(EMAIL)).thenReturn(true);
            when(userService.findByEmail(EMAIL)).thenReturn(validUser);

            // Act
            authService.resendEmailVerification(EMAIL);

            // Assert
            verify(verificationService, never()).sendEmailVerification(any());
        }
    }

    // ========================================================================
    // TESTS: verifyEmail()
    // ========================================================================

    @Nested
    @DisplayName("verifyEmail() - Verificar email do usuário")
    class VerifyEmailTests {

        private VerificationToken verificationToken;

        @BeforeEach
        void setUp() {
            validUser.setEmailVerified(false);

            verificationToken = new VerificationToken();
            verificationToken.setToken(TOKEN);
            verificationToken.setUser(validUser);
            verificationToken.setType(TokenType.EMAIL_VERIFICATION);
            verificationToken.setExpiryDate(LocalDateTime.now().plusHours(24));
        }

        @Test
        @DisplayName("Deveria validar token e marcar email como verificado")
        void shouldValidateTokenAndMarkEmailAsVerified() {
            // Arrange
            when(verificationService.validateToken(TOKEN, TokenType.EMAIL_VERIFICATION))
                    .thenReturn(verificationToken);
            when(userService.save(validUser)).thenReturn(validUser);

            // Act
            authService.verifyEmail(TOKEN);

            // Assert
            assertThat(validUser.isEmailVerified()).isTrue();
            verify(userService).save(validUser);
        }

        @Test
        @DisplayName("Deveria deletar token após verificação bem-sucedida")
        void shouldDeleteToken_AfterSuccessfulVerification() {
            // Arrange
            when(verificationService.validateToken(TOKEN, TokenType.EMAIL_VERIFICATION))
                    .thenReturn(verificationToken);
            when(userService.save(validUser)).thenReturn(validUser);

            // Act
            authService.verifyEmail(TOKEN);

            // Assert
            verify(verificationService).deleteByUserIdAndType(validUser.getId(),
                    TokenType.EMAIL_VERIFICATION);
        }
    }

    // ========================================================================
    // TESTS: sendPasswordResetEmail()
    // ========================================================================

    @Nested
    @DisplayName("sendPasswordResetEmail() - Enviar email de reset de senha")
    class SendPasswordResetEmailTests {

        @Test
        @DisplayName("Deveria enviar email quando usuário existe")
        void shouldSendEmail_WhenUserExists() {
            // Arrange
            when(userService.findByEmailOptional(EMAIL)).thenReturn(Optional.of(validUser));

            // Act
            authService.sendPasswordResetEmail(EMAIL);

            // Assert
            verify(verificationService).sendPasswordReset(validUser);
        }

        @Test
        @DisplayName("Deveria não enviar email quando usuário não existe")
        void shouldNotSendEmail_WhenUserDoesNotExist() {
            // Arrange
            when(userService.findByEmailOptional(EMAIL)).thenReturn(Optional.empty());

            // Act
            authService.sendPasswordResetEmail(EMAIL);

            // Assert
            verify(verificationService, never()).sendPasswordReset(any());
        }
    }

    // ========================================================================
    // TESTS: resetPassword()
    // ========================================================================

    @Nested
    @DisplayName("resetPassword() - Resetar senha do usuário")
    class ResetPasswordTests {

        private VerificationToken resetToken;

        @BeforeEach
        void setUp() {
            resetToken = new VerificationToken();
            resetToken.setToken(TOKEN);
            resetToken.setUser(validUser);
            resetToken.setType(TokenType.PASSWORD_RESET);
            resetToken.setExpiryDate(LocalDateTime.now().plusHours(1));
        }

        @Test
        @DisplayName("Deveria validar token e atualizar senha")
        void shouldValidateTokenAndUpdatePassword() {
            // Arrange
            when(verificationService.validateToken(TOKEN, TokenType.PASSWORD_RESET))
                    .thenReturn(resetToken);

            // Act
            authService.resetPassword(TOKEN, NEW_PASSWORD);

            // Assert
            verify(userService).setNewPassword(validUser, NEW_PASSWORD);
        }

        @Test
        @DisplayName("Deveria deletar token após reset bem-sucedido")
        void shouldDeleteToken_AfterSuccessfulReset() {
            // Arrange
            when(verificationService.validateToken(TOKEN, TokenType.PASSWORD_RESET))
                    .thenReturn(resetToken);

            // Act
            authService.resetPassword(TOKEN, NEW_PASSWORD);

            // Assert
            verify(verificationService).deleteByUserIdAndType(validUser.getId(),
                    TokenType.PASSWORD_RESET);
        }
    }

    // ========================================================================
    // TESTS: logout()
    // ========================================================================

    @Nested
    @DisplayName("logout() - Logout de dispositivo único")
    class LogoutTests {

        @Test
        @DisplayName("Deveria revogar ambos os tokens quando são válidos")
        void shouldRevokeBothTokens_WhenValid() {
            // Arrange
            when(jwtUtil.validateToken(ACCESS_TOKEN)).thenReturn(true);
            when(jwtUtil.validateToken(REFRESH_TOKEN)).thenReturn(true);

            // Act
            authService.logout(ACCESS_TOKEN, REFRESH_TOKEN);

            // Assert
            verify(tokenRevocationService).revokeTokenPair(ACCESS_TOKEN, REFRESH_TOKEN);
        }

        @Test
        @DisplayName("Deveria lançar exceção quando access token é inválido")
        void shouldThrowException_WhenAccessTokenInvalid() {
            // Arrange
            when(jwtUtil.validateToken(ACCESS_TOKEN)).thenReturn(false);

            // Act & Assert
            assertThatThrownBy(() -> authService.logout(ACCESS_TOKEN, REFRESH_TOKEN))
                    .isInstanceOf(InvalidTokenException.class).hasMessage("Tokens inválidos");

            verify(tokenRevocationService, never()).revokeTokenPair(any(), any());
        }

        @Test
        @DisplayName("Deveria lançar exceção quando refresh token é inválido")
        void shouldThrowException_WhenRefreshTokenInvalid() {
            // Arrange
            when(jwtUtil.validateToken(ACCESS_TOKEN)).thenReturn(true);
            when(jwtUtil.validateToken(REFRESH_TOKEN)).thenReturn(false);

            // Act & Assert
            assertThatThrownBy(() -> authService.logout(ACCESS_TOKEN, REFRESH_TOKEN))
                    .isInstanceOf(InvalidTokenException.class).hasMessage("Tokens inválidos");

            verify(tokenRevocationService, never()).revokeTokenPair(any(), any());
        }
    }

    // ========================================================================
    // TESTS: logoutAllDevices()
    // ========================================================================

    @Nested
    @DisplayName("logoutAllDevices() - Logout global")
    class LogoutAllDevicesTests {

        @Test
        @DisplayName("Deveria revogar todos os tokens do usuário")
        void shouldRevokeAllUserTokens() {
            // Act
            authService.logoutAllDevices(USERNAME);

            // Assert
            verify(tokenRevocationService).revokeAllUserTokens(USERNAME);
        }
    }
}
