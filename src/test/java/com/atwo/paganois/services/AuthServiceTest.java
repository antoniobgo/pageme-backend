package com.atwo.paganois.services;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import java.time.LocalDateTime;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InOrder;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import com.atwo.paganois.dtos.LoginRequest;
import com.atwo.paganois.dtos.LoginResponse;
import com.atwo.paganois.dtos.RefreshRequest;
import com.atwo.paganois.dtos.RegisterRequest;
import com.atwo.paganois.dtos.RegisterResponse;
import com.atwo.paganois.entities.Role;
import com.atwo.paganois.entities.TokenType;
import com.atwo.paganois.entities.User;
import com.atwo.paganois.entities.VerificationToken;
import com.atwo.paganois.exceptions.UserAlreadyExistsException;
import com.atwo.paganois.security.JwtUtil;

/**
 * Unit tests for AuthService
 * 
 * Tests cover: 1. Login flow (authentication + JWT generation) 2. Token refresh flow 3. User
 * registration flow 4. Email verification 5. Password reset request 6. Password reset execution
 */
@ExtendWith(MockitoExtension.class)
@DisplayName("AuthService - Unit Tests")
class AuthServiceTest {

    @Mock
    private UserService userService;

    @Mock
    private CustomUserDetailsService userDetailsService;

    @Mock
    private VerificationService verificationService;

    @Mock
    private AuthenticationManager authenticationManager;

    @Mock
    private PasswordEncoder passwordEncoder;

    @Mock
    private JwtUtil jwtUtil;

    @InjectMocks
    private AuthService authService;

    private User validUser;
    private Role userRole;
    private LoginRequest loginRequest;
    private RegisterRequest registerRequest;
    private Authentication authentication;

    private static final String USERNAME = "testuser";
    private static final String EMAIL = "test@example.com";
    private static final String PASSWORD = "password123";
    private static final String ENCODED_PASSWORD = "encodedPassword123";
    private static final String ACCESS_TOKEN = "access.jwt.token";
    private static final String REFRESH_TOKEN = "refresh.jwt.token";
    private static final String NEW_ACCESS_TOKEN = "new.access.jwt.token";
    private static final String RESET_TOKEN = "reset-token-uuid";
    private static final String EMAIL_VERIFICATION_TOKEN = "email-verification-token-uuid";

    @BeforeEach
    void setUp() {
        // Setup Role
        userRole = new Role();
        userRole.setId(1L);
        userRole.setAuthority("ROLE_USER");

        // Setup User
        validUser = new User();
        validUser.setId(1L);
        validUser.setUsername(USERNAME);
        validUser.setEmail(EMAIL);
        validUser.setPassword(ENCODED_PASSWORD);
        validUser.setRole(userRole);
        validUser.setEnabled(true);
        validUser.setEmailVerified(false);

        // Setup LoginRequest
        loginRequest = new LoginRequest(USERNAME, PASSWORD);

        // Setup RegisterRequest
        registerRequest = new RegisterRequest(USERNAME, PASSWORD, EMAIL);

        // Setup Authentication mock
        authentication = mock(Authentication.class);
    }

    // ========================================================================
    // TESTS: login()
    // ========================================================================

    @Nested
    @DisplayName("login() - Authenticate user and generate tokens")
    class LoginTests {

        @BeforeEach
        void setUp() {
            when(authentication.getPrincipal()).thenReturn(validUser);
            when(authenticationManager.authenticate(any(UsernamePasswordAuthenticationToken.class)))
                    .thenReturn(authentication);
            when(jwtUtil.generateToken(any(UserDetails.class))).thenReturn(ACCESS_TOKEN);
            when(jwtUtil.generateRefreshToken(any(UserDetails.class))).thenReturn(REFRESH_TOKEN);
        }

        @Test
        @DisplayName("Should authenticate user with AuthenticationManager")
        void shouldAuthenticateUser_WithAuthenticationManager() {
            // Act
            authService.login(loginRequest);

            // Assert
            ArgumentCaptor<UsernamePasswordAuthenticationToken> authCaptor =
                    ArgumentCaptor.forClass(UsernamePasswordAuthenticationToken.class);
            verify(authenticationManager).authenticate(authCaptor.capture());

            UsernamePasswordAuthenticationToken authToken = authCaptor.getValue();
            assertThat(authToken.getPrincipal()).isEqualTo(USERNAME);
            assertThat(authToken.getCredentials()).isEqualTo(PASSWORD);
        }

        @Test
        @DisplayName("Should generate access token for authenticated user")
        void shouldGenerateAccessToken_ForAuthenticatedUser() {
            // Act
            LoginResponse response = authService.login(loginRequest);

            // Assert
            verify(jwtUtil, times(1)).generateToken(validUser);
            assertThat(response.accessToken()).isEqualTo(ACCESS_TOKEN);
        }

        @Test
        @DisplayName("Should generate refresh token for authenticated user")
        void shouldGenerateRefreshToken_ForAuthenticatedUser() {
            // Act
            LoginResponse response = authService.login(loginRequest);

            // Assert
            verify(jwtUtil, times(1)).generateRefreshToken(validUser);
            assertThat(response.refreshToken()).isEqualTo(REFRESH_TOKEN);
        }

        @Test
        @DisplayName("Should return LoginResponse with both tokens")
        void shouldReturnLoginResponse_WithBothTokens() {
            // Act
            LoginResponse response = authService.login(loginRequest);

            // Assert
            assertThat(response).isNotNull();
            assertThat(response.accessToken()).isEqualTo(ACCESS_TOKEN);
            assertThat(response.refreshToken()).isEqualTo(REFRESH_TOKEN);
        }

        @Test
        @DisplayName("Should extract UserDetails from authentication principal")
        void shouldExtractUserDetails_FromAuthenticationPrincipal() {
            // Act
            authService.login(loginRequest);

            // Assert
            verify(authentication, times(1)).getPrincipal();
        }
    }

    // ========================================================================
    // TESTS: refresh()
    // ========================================================================

    @Nested
    @DisplayName("refresh() - Refresh access token")
    class RefreshTests {

        private RefreshRequest refreshRequest;

        @BeforeEach
        void setUp() {
            refreshRequest = new RefreshRequest(REFRESH_TOKEN);
            when(jwtUtil.validateToken(REFRESH_TOKEN)).thenReturn(true);
            when(jwtUtil.extractUsername(REFRESH_TOKEN)).thenReturn(USERNAME);
            when(userDetailsService.loadUserByUsername(USERNAME)).thenReturn(validUser);
            when(jwtUtil.generateToken(validUser)).thenReturn(NEW_ACCESS_TOKEN);
        }

        @Test
        @DisplayName("Should validate refresh token")
        void shouldValidateRefreshToken() {

            // Act
            authService.refresh(refreshRequest);

            // Assert
            verify(jwtUtil, times(1)).validateToken(REFRESH_TOKEN);
        }

        @Test
        @DisplayName("Should extract username from refresh token")
        void shouldExtractUsername_FromRefreshToken() {

            // Act
            authService.refresh(refreshRequest);

            // Assert
            verify(jwtUtil, times(1)).extractUsername(REFRESH_TOKEN);
        }

        @Test
        @DisplayName("Should load user by extracted username")
        void shouldLoadUser_ByExtractedUsername() {

            // Act
            authService.refresh(refreshRequest);

            // Assert
            verify(userDetailsService, times(1)).loadUserByUsername(USERNAME);
        }

        @Test
        @DisplayName("Should generate new access token")
        void shouldGenerateNewAccessToken() {

            // Act
            LoginResponse response = authService.refresh(refreshRequest);

            // Assert
            verify(jwtUtil, times(1)).generateToken(validUser);
            assertThat(response.accessToken()).isEqualTo(NEW_ACCESS_TOKEN);
        }

        @Test
        @DisplayName("Should return same refresh token")
        void shouldReturnSameRefreshToken() {

            // Act
            LoginResponse response = authService.refresh(refreshRequest);

            // Assert
            assertThat(response.refreshToken()).isEqualTo(REFRESH_TOKEN);
        }

        @Test
        @DisplayName("Should return LoginResponse with new access token and same refresh token")
        void shouldReturnLoginResponse_WithNewAccessAndSameRefresh() {

            // Act
            LoginResponse response = authService.refresh(refreshRequest);

            // Assert
            assertThat(response).isNotNull();
            assertThat(response.accessToken()).isEqualTo(NEW_ACCESS_TOKEN);
            assertThat(response.refreshToken()).isEqualTo(REFRESH_TOKEN);
        }
    }

    // ========================================================================
    // TESTS: register()
    // ========================================================================

    @Nested
    @DisplayName("register() - Register new user")
    class RegisterTests {

        @Test
        @DisplayName("Should throw exception when username already exists")
        void shouldThrowException_WhenUsernameExists() {
            // Arrange
            when(userDetailsService.existsByUsername(USERNAME)).thenReturn(true);

            // Act & Assert
            assertThatThrownBy(() -> authService.register(registerRequest))
                    .isInstanceOf(UserAlreadyExistsException.class)
                    .hasMessage("Username ou email já está em uso");
        }

        @Test
        @DisplayName("Should throw exception when email already exists")
        void shouldThrowException_WhenEmailExists() {
            // Arrange
            when(userDetailsService.existsByEmail(EMAIL)).thenReturn(true);

            // Act & Assert
            assertThatThrownBy(() -> authService.register(registerRequest))
                    .isInstanceOf(UserAlreadyExistsException.class)
                    .hasMessage("Username ou email já está em uso");
        }

        @Test
        @DisplayName("Should throw exception when both username and email exist")
        void shouldThrowException_WhenBothExist() {
            // Arrange
            when(userDetailsService.existsByUsername(USERNAME)).thenReturn(true);

            // Act & Assert
            assertThatThrownBy(() -> authService.register(registerRequest))
                    .isInstanceOf(UserAlreadyExistsException.class)
                    .hasMessage("Username ou email já está em uso");
        }

        @Test
        @DisplayName("Should encode password before saving user")
        void shouldEncodePassword_BeforeSavingUser() {
            // Arrange
            when(userDetailsService.existsByUsername(USERNAME)).thenReturn(false);
            when(userDetailsService.existsByEmail(EMAIL)).thenReturn(false);
            when(passwordEncoder.encode(PASSWORD)).thenReturn(ENCODED_PASSWORD);
            when(userService.registerUser(USERNAME, ENCODED_PASSWORD, EMAIL)).thenReturn(validUser);

            // Act
            authService.register(registerRequest);

            // Assert
            verify(passwordEncoder, times(1)).encode(PASSWORD);
        }

        @Test
        @DisplayName("Should save user with correct details")
        void shouldSaveUser_WithCorrectDetails() {
            // Arrange
            when(userDetailsService.existsByUsername(USERNAME)).thenReturn(false);
            when(userDetailsService.existsByEmail(EMAIL)).thenReturn(false);
            when(passwordEncoder.encode(PASSWORD)).thenReturn(ENCODED_PASSWORD);
            when(userService.registerUser(USERNAME, ENCODED_PASSWORD, EMAIL)).thenReturn(validUser);

            // ArgumentCaptor<User> userCaptor = ArgumentCaptor.forClass(User.class);

            // Act
            authService.register(registerRequest);

            // Assert
            verify(userService, times(1)).registerUser(USERNAME, ENCODED_PASSWORD, EMAIL);
        }

        @Test
        @DisplayName("Should send email verification after saving user")
        void shouldSendEmailVerification_AfterSavingUser() {
            // Arrange
            when(userDetailsService.existsByUsername(USERNAME)).thenReturn(false);
            when(userDetailsService.existsByEmail(EMAIL)).thenReturn(false);
            when(passwordEncoder.encode(PASSWORD)).thenReturn(ENCODED_PASSWORD);
            when(userService.registerUser(USERNAME, ENCODED_PASSWORD, EMAIL)).thenReturn(validUser);

            // Act
            authService.register(registerRequest);

            // Assert
            // verify(verificationService, times(1)).sendEmailVerification(validUser);
            InOrder inOrder = inOrder(userService, verificationService);
            inOrder.verify(userService).registerUser(USERNAME, ENCODED_PASSWORD, EMAIL);
            inOrder.verify(verificationService).sendEmailVerification(validUser);
        }

        @Test
        @DisplayName("Should return RegisterResponse with user details")
        void shouldReturnRegisterResponse_WithUserDetails() {
            // Arrange
            when(userDetailsService.existsByUsername(USERNAME)).thenReturn(false);
            when(userDetailsService.existsByEmail(EMAIL)).thenReturn(false);
            when(passwordEncoder.encode(PASSWORD)).thenReturn(ENCODED_PASSWORD);
            when(userService.registerUser(USERNAME, ENCODED_PASSWORD, EMAIL)).thenReturn(validUser);

            // Act
            RegisterResponse response = authService.register(registerRequest);

            // Assert
            assertThat(response).isNotNull();
            assertThat(response.id()).isEqualTo(validUser.getId());
            assertThat(response.username()).isEqualTo(validUser.getUsername());
            assertThat(response.isEmailVerified()).isFalse();
        }
    }

    // ========================================================================
    // TESTS: verifyEmail()
    // ========================================================================

    @Nested
    @DisplayName("verifyEmail() - Verify user email")
    class VerifyEmailTests {

        private static final String TOKEN = "verification-token";

        @Test
        @DisplayName("Should validate valid token")
        void shouldDelegateToVerificationService() {
            // Arrange
            VerificationToken verificationToken;
            verificationToken = new VerificationToken();
            verificationToken.setToken(EMAIL_VERIFICATION_TOKEN);
            verificationToken.setUser(validUser);
            verificationToken.setType(TokenType.EMAIL_VERIFICATION);
            verificationToken.setExpiryDate(LocalDateTime.now().plusHours(1));
            when(verificationService.validateToken(EMAIL_VERIFICATION_TOKEN,
                    TokenType.EMAIL_VERIFICATION)).thenReturn(verificationToken);

            // Act
            authService.verifyEmail(EMAIL_VERIFICATION_TOKEN);

            // Assert
            verify(verificationService, times(1)).validateToken(EMAIL_VERIFICATION_TOKEN,
                    TokenType.EMAIL_VERIFICATION);
        }

        @Test
        @DisplayName("Should set user's emailVerified to true and save")
        void shouldPassToken_ToVerificationService() {
            // Arrange
            VerificationToken verificationToken;
            verificationToken = new VerificationToken();
            verificationToken.setToken(EMAIL_VERIFICATION_TOKEN);
            verificationToken.setUser(validUser);
            verificationToken.setType(TokenType.EMAIL_VERIFICATION);
            verificationToken.setExpiryDate(LocalDateTime.now().plusHours(1));
            when(verificationService.validateToken(EMAIL_VERIFICATION_TOKEN,
                    TokenType.EMAIL_VERIFICATION)).thenReturn(verificationToken);

            // Act
            authService.verifyEmail(EMAIL_VERIFICATION_TOKEN);

            // Assert
            verify(userService, times(1)).save(validUser);
            assertThat(validUser.isEmailVerified()).isTrue();
        }
    }

    // ========================================================================
    // TESTS: sendPasswordResetEmail()
    // ========================================================================

    @Nested
    @DisplayName("sendPasswordResetEmail() - Send password reset email")
    class SendPasswordResetEmailTests {

        @Test
        @DisplayName("Should delegate to VerificationService")
        void shouldDelegateToVerificationService() {
            // Act
            authService.sendPasswordResetEmail(EMAIL);

            // Assert
            verify(verificationService, times(1)).sendPasswordReset(EMAIL);
        }

        @Test
        @DisplayName("Should pass email to verification service")
        void shouldPassEmail_ToVerificationService() {
            // Arrange
            ArgumentCaptor<String> emailCaptor = ArgumentCaptor.forClass(String.class);

            // Act
            authService.sendPasswordResetEmail(EMAIL);

            // Assert
            verify(verificationService).sendPasswordReset(emailCaptor.capture());
            assertThat(emailCaptor.getValue()).isEqualTo(EMAIL);
        }
    }

    // ========================================================================
    // TESTS: resetPassword()
    // ========================================================================

    @Nested
    @DisplayName("resetPassword() - Reset user password")
    class ResetPasswordTests {

        private static final String NEW_PASSWORD = "newPassword123";
        private static final String NEW_ENCODED_PASSWORD = "encodedNewPassword123";
        private VerificationToken resetToken;

        @BeforeEach
        void setUp() {
            resetToken = new VerificationToken();
            resetToken.setToken(RESET_TOKEN);
            resetToken.setUser(validUser);
            resetToken.setType(TokenType.PASSWORD_RESET);
            resetToken.setExpiryDate(LocalDateTime.now().plusHours(1));
        }

        @Test
        @DisplayName("Should validate token with PASSWORD_RESET type")
        void shouldValidateToken_WithPasswordResetType() {
            // Arrange
            when(verificationService.validateToken(RESET_TOKEN, TokenType.PASSWORD_RESET))
                    .thenReturn(resetToken);
            when(passwordEncoder.encode(NEW_PASSWORD)).thenReturn(NEW_ENCODED_PASSWORD);

            // Act
            authService.resetPassword(RESET_TOKEN, NEW_PASSWORD);

            // Assert
            verify(verificationService, times(1)).validateToken(RESET_TOKEN,
                    TokenType.PASSWORD_RESET);
        }

        @Test
        @DisplayName("Should encode new password")
        void shouldEncodeNewPassword() {
            // Arrange
            when(verificationService.validateToken(RESET_TOKEN, TokenType.PASSWORD_RESET))
                    .thenReturn(resetToken);
            when(passwordEncoder.encode(NEW_PASSWORD)).thenReturn(NEW_ENCODED_PASSWORD);

            // Act
            authService.resetPassword(RESET_TOKEN, NEW_PASSWORD);

            // Assert
            verify(passwordEncoder, times(1)).encode(NEW_PASSWORD);
        }

        @Test
        @DisplayName("Should call userService to update user's password with encoded new password")
        void shouldUpdateUserPassword_WithEncodedPassword() {
            // Arrange
            when(verificationService.validateToken(RESET_TOKEN, TokenType.PASSWORD_RESET))
                    .thenReturn(resetToken);
            when(passwordEncoder.encode(NEW_PASSWORD)).thenReturn(NEW_ENCODED_PASSWORD);

            // Act
            authService.resetPassword(RESET_TOKEN, NEW_PASSWORD);

            // Assert

            verify(userService).setNewPassword(validUser, NEW_ENCODED_PASSWORD);
        }
    }
}
