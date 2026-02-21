package com.atwo.paganois.user.services;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
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
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import com.atwo.paganois.auth.entities.TokenType;
import com.atwo.paganois.auth.entities.VerificationToken;
import com.atwo.paganois.auth.exceptions.AccountDisabledException;
import com.atwo.paganois.auth.exceptions.EmailAlreadyTakenException;
import com.atwo.paganois.auth.exceptions.LoggedUserAndChangeEmailTokenMismatchException;
import com.atwo.paganois.auth.exceptions.WrongPasswordException;
import com.atwo.paganois.auth.services.VerificationService;
import com.atwo.paganois.user.dtos.UserDTO;
import com.atwo.paganois.user.entities.Role;
import com.atwo.paganois.user.entities.User;
import com.atwo.paganois.user.exceptions.UserNotFoundException;
import com.atwo.paganois.user.repositories.RoleRepository;
import com.atwo.paganois.user.repositories.UserRepository;

/**
 * Unit tests for UserService
 * 
 * Structure: - save() - User persistence - getAuthenticatedUserProfile() - Profile retrieval with
 * validation - registerUser() - User registration - setNewPassword() - Password update (no old
 * password check) - updatePassword() - Password update (with old password validation) -
 * requestEmailChange() - Email change initiation - confirmEmailChange() - Email change confirmation
 * - validateNewEmail() - Email validation logic - loadByUsername() - User lookup - Other utility
 * methods
 */
@ExtendWith(MockitoExtension.class)
@DisplayName("UserService - Unit Tests")
class UserServiceTest {

    @Mock
    private UserRepository userRepository;

    @Mock
    private RoleRepository roleRepository;

    @Mock
    private PasswordEncoder passwordEncoder;

    @Mock
    private VerificationService verificationService;

    @InjectMocks
    private UserService userService;

    private User validUser;
    private Role userRole;

    private static final String USERNAME = "testuser";
    private static final String EMAIL = "test@example.com";
    private static final String NEW_EMAIL = "new@example.com";
    private static final String PASSWORD = "password123";
    private static final String ENCODED_PASSWORD = "$2a$10$encodedPassword";
    private static final String NEW_PASSWORD = "newPassword456";
    private static final String ENCODED_NEW_PASSWORD = "$2a$10$encodedNewPassword";
    private static final String TOKEN = "test-token-uuid";

    @BeforeEach
    void setUp() {
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
    // TESTS: save()
    // ========================================================================

    @Nested
    @DisplayName("save() - Salvar usuário no repositório")
    class SaveTests {

        @Test
        @DisplayName("Deveria salvar usuário e retornar usuário salvo")
        void shouldSaveUser_AndReturnSavedUser() {
            // Arrange
            when(userRepository.save(validUser)).thenReturn(validUser);

            // Act
            User result = userService.save(validUser);

            // Assert
            assertThat(result).isNotNull().isEqualTo(validUser);
            verify(userRepository).save(validUser);
        }

        @Test
        @DisplayName("Deveria delegar operação de save para o repositório")
        void shouldDelegateSave_ToRepository() {
            // Arrange
            when(userRepository.save(validUser)).thenReturn(validUser);

            // Act
            userService.save(validUser);

            // Assert
            verify(userRepository).save(validUser);
        }
    }

    // ========================================================================
    // TESTS: getAuthenticatedUserProfile()
    // ========================================================================

    @Nested
    @DisplayName("getAuthenticatedUserProfile() - Obter perfil do usuário autenticado")
    class GetAuthenticatedUserProfileTests {

        @Test
        @DisplayName("Deveria retornar UserDTO quando usuário está habilitado e existe")
        void shouldReturnUserDTO_WhenUserIsEnabledAndExists() {
            // Arrange
            when(userRepository.existsByUsername(USERNAME)).thenReturn(true);

            // Act
            UserDTO result = userService.getAuthenticatedUserProfile(validUser);

            // Assert
            assertThat(result).isNotNull();
            assertThat(result.getUsername()).isEqualTo(USERNAME);
            assertThat(result.getEmail()).isEqualTo(EMAIL);
            verify(userRepository).existsByUsername(USERNAME);
        }

        @Test
        @DisplayName("Deveria lançar AccountDisabledException quando usuário está desabilitado")
        void shouldThrowAccountDisabledException_WhenUserIsDisabled() {
            // Arrange
            validUser.setEnabled(false);

            // Act & Assert
            assertThatThrownBy(() -> userService.getAuthenticatedUserProfile(validUser))
                    .isInstanceOf(AccountDisabledException.class).hasMessage("Conta desativada");

            verify(userRepository, never()).existsByUsername(any());
        }

        @Test
        @DisplayName("Deveria lançar UserNotFoundException quando usuário não existe no repositório")
        void shouldThrowUserNotFoundException_WhenUserNotInRepository() {
            // Arrange
            when(userRepository.existsByUsername(USERNAME)).thenReturn(false);

            // Act & Assert
            assertThatThrownBy(() -> userService.getAuthenticatedUserProfile(validUser))
                    .isInstanceOf(UserNotFoundException.class).hasMessage("Usuário não encontrado");

            verify(userRepository).existsByUsername(USERNAME);
        }
    }

    // ========================================================================
    // TESTS: registerUser()
    // ========================================================================

    @Nested
    @DisplayName("registerUser() - Registrar novo usuário")
    class RegisterUserTests {

        @Test
        @DisplayName("Deveria criar usuário com todos os campos configurados corretamente")
        void shouldCreateUser_WithAllFieldsSetCorrectly() {
            // Arrange
            when(roleRepository.findByAuthority("ROLE_USER")).thenReturn(userRole);
            when(userRepository.save(any(User.class))).thenReturn(validUser);

            ArgumentCaptor<User> captor = ArgumentCaptor.forClass(User.class);

            // Act
            userService.registerUser(USERNAME, ENCODED_PASSWORD, EMAIL);

            // Assert
            verify(userRepository).save(captor.capture());
            User capturedUser = captor.getValue();

            assertThat(capturedUser.getUsername()).isEqualTo(USERNAME);
            assertThat(capturedUser.getPassword()).isEqualTo(ENCODED_PASSWORD);
            assertThat(capturedUser.getEmail()).isEqualTo(EMAIL);
            assertThat(capturedUser.getRole()).isEqualTo(userRole);
        }

        @Test
        @DisplayName("Deveria buscar ROLE_USER do repositório")
        void shouldFetchRoleUser_FromRepository() {
            // Arrange
            when(roleRepository.findByAuthority("ROLE_USER")).thenReturn(userRole);
            when(userRepository.save(any(User.class))).thenReturn(validUser);

            // Act
            userService.registerUser(USERNAME, ENCODED_PASSWORD, EMAIL);

            // Assert
            verify(roleRepository).findByAuthority("ROLE_USER");
        }

        @Test
        @DisplayName("Deveria salvar usuário e retornar usuário salvo")
        void shouldSaveUser_AndReturnSavedUser() {
            // Arrange
            when(roleRepository.findByAuthority("ROLE_USER")).thenReturn(userRole);
            when(userRepository.save(any(User.class))).thenReturn(validUser);

            // Act
            User result = userService.registerUser(USERNAME, ENCODED_PASSWORD, EMAIL);

            // Assert
            assertThat(result).isNotNull().isEqualTo(validUser);
            verify(userRepository).save(any(User.class));
        }
    }

    // ========================================================================
    // TESTS: setNewPassword()
    // ========================================================================

    @Nested
    @DisplayName("setNewPassword() - Atualizar senha do usuário (sem verificação de senha antiga)")
    class SetNewPasswordTests {

        @Test
        @DisplayName("Deveria encodar e atualizar senha do usuário")
        void shouldEncodeAndUpdateUserPassword() {
            // Arrange
            when(passwordEncoder.encode(NEW_PASSWORD)).thenReturn(ENCODED_NEW_PASSWORD);
            when(userRepository.save(validUser)).thenReturn(validUser);

            // Act
            userService.setNewPassword(validUser, NEW_PASSWORD);

            // Assert
            assertThat(validUser.getPassword()).isEqualTo(ENCODED_NEW_PASSWORD);
            verify(passwordEncoder).encode(NEW_PASSWORD);
            verify(userRepository).save(validUser);
        }

        @Test
        @DisplayName("Deveria salvar usuário após atualizar senha")
        void shouldSaveUser_AfterUpdatingPassword() {
            // Arrange
            when(passwordEncoder.encode(NEW_PASSWORD)).thenReturn(ENCODED_NEW_PASSWORD);
            when(userRepository.save(validUser)).thenReturn(validUser);

            // Act
            userService.setNewPassword(validUser, NEW_PASSWORD);

            // Assert
            verify(userRepository).save(validUser);
        }
    }

    // ========================================================================
    // TESTS: updatePassword()
    // ========================================================================

    @Nested
    @DisplayName("updatePassword() - Atualizar senha com validação de senha antiga")
    class UpdatePasswordTests {

        @Test
        @DisplayName("Deveria lançar WrongPasswordException quando senha antiga está incorreta")
        void shouldThrowWrongPasswordException_WhenOldPasswordIsIncorrect() {
            // Arrange
            String wrongOldPassword = "wrongPassword";
            when(passwordEncoder.encode(wrongOldPassword)).thenReturn("$2a$10$wrong");

            // Act & Assert
            assertThatThrownBy(
                    () -> userService.updatePassword(validUser, NEW_PASSWORD, wrongOldPassword))
                            .isInstanceOf(WrongPasswordException.class)
                            .hasMessage("Senha atual incorreta");

            verify(userRepository, never()).save(any());
        }

        @Test
        @DisplayName("Deveria atualizar senha quando senha antiga está correta")
        void shouldUpdatePassword_WhenOldPasswordIsCorrect() {
            // Arrange
            when(passwordEncoder.encode(PASSWORD)).thenReturn(ENCODED_PASSWORD);
            when(passwordEncoder.encode(NEW_PASSWORD)).thenReturn(ENCODED_NEW_PASSWORD);
            when(userRepository.save(validUser)).thenReturn(validUser);

            // Act
            userService.updatePassword(validUser, NEW_PASSWORD, PASSWORD);

            // Assert
            assertThat(validUser.getPassword()).isEqualTo(ENCODED_NEW_PASSWORD);
            verify(userRepository).save(validUser);
        }
    }

    // ========================================================================
    // TESTS: requestEmailChange()
    // ========================================================================

    @Nested
    @DisplayName("requestEmailChange() - Solicitar mudança de email")
    class RequestEmailChangeTests {

        @Test
        @DisplayName("Deveria lançar EmailAlreadyTakenException quando novo email é o mesmo que o atual")
        void shouldThrowEmailAlreadyTakenException_WhenNewEmailIsSameAsCurrent() {
            // Act & Assert
            assertThatThrownBy(() -> userService.requestEmailChange(validUser, EMAIL))
                    .isInstanceOf(EmailAlreadyTakenException.class)
                    .hasMessage("Este já é seu email atual");

            verify(verificationService, never()).sendEmailChangeVerification(any(), any());
        }

        @Test
        @DisplayName("Deveria lançar EmailAlreadyTakenException quando novo email já está em uso")
        void shouldThrowEmailAlreadyTakenException_WhenNewEmailIsAlreadyTaken() {
            // Arrange
            when(userRepository.existsByEmailAndVerified(NEW_EMAIL)).thenReturn(true);

            // Act & Assert
            assertThatThrownBy(() -> userService.requestEmailChange(validUser, NEW_EMAIL))
                    .isInstanceOf(EmailAlreadyTakenException.class)
                    .hasMessage("Email já está em uso");

            verify(verificationService, never()).sendEmailChangeVerification(any(), any());
        }

        @Test
        @DisplayName("Deveria enviar verificação de mudança de email quando novo email é válido")
        void shouldSendEmailChangeVerification_WhenNewEmailIsValid() {
            // Arrange
            when(userRepository.existsByEmailAndVerified(NEW_EMAIL)).thenReturn(false);

            // Act
            userService.requestEmailChange(validUser, NEW_EMAIL);

            // Assert
            verify(verificationService).sendEmailChangeVerification(validUser, NEW_EMAIL);
        }
    }

    // ========================================================================
    // TESTS: confirmEmailChange()
    // ========================================================================

    @Nested
    @DisplayName("confirmEmailChange() - Confirmar mudança de email")
    class ConfirmEmailChangeTests {

        private VerificationToken emailChangeToken;

        @BeforeEach
        void setUp() {
            emailChangeToken = new VerificationToken();
            emailChangeToken.setToken(TOKEN);
            emailChangeToken.setUser(validUser);
            emailChangeToken.setType(TokenType.EMAIL_CHANGE);
            emailChangeToken.setPendingEmail(NEW_EMAIL);
            emailChangeToken.setExpiryDate(LocalDateTime.now().plusHours(1));
        }

        @Test
        @DisplayName("Deveria validar token com tipo EMAIL_CHANGE")
        void shouldValidateToken_WithEmailChangeType() {
            // Arrange
            when(verificationService.validateToken(TOKEN, TokenType.EMAIL_CHANGE))
                    .thenReturn(emailChangeToken);
            when(userRepository.existsByEmailAndVerified(NEW_EMAIL)).thenReturn(false);
            when(userRepository.save(validUser)).thenReturn(validUser);

            // Act
            userService.confirmEmailChange(validUser, TOKEN);

            // Assert
            verify(verificationService).validateToken(TOKEN, TokenType.EMAIL_CHANGE);
        }

        @Test
        @DisplayName("Deveria lançar exceção quando token não pertence ao usuário autenticado")
        void shouldThrowException_WhenTokenDoesNotBelongToAuthenticatedUser() {
            // Arrange
            User anotherUser = new User();
            anotherUser.setId(2L);
            anotherUser.setUsername("anotheruser");
            anotherUser.setEmail("another@example.com");

            emailChangeToken.setUser(anotherUser);

            when(verificationService.validateToken(TOKEN, TokenType.EMAIL_CHANGE))
                    .thenReturn(emailChangeToken);

            // Act & Assert
            assertThatThrownBy(() -> userService.confirmEmailChange(validUser, TOKEN))
                    .isInstanceOf(LoggedUserAndChangeEmailTokenMismatchException.class)
                    .hasMessage("Token de troca de email não pertence ao usuário autenticado");
        }

        @Test
        @DisplayName("Deveria atualizar email e deletar token quando confirmação é bem-sucedida")
        void shouldUpdateEmailAndDeleteToken_WhenConfirmationIsSuccessful() {
            // Arrange
            when(verificationService.validateToken(TOKEN, TokenType.EMAIL_CHANGE))
                    .thenReturn(emailChangeToken);
            when(userRepository.existsByEmailAndVerified(NEW_EMAIL)).thenReturn(false);
            when(userRepository.save(validUser)).thenReturn(validUser);

            // Act
            String result = userService.confirmEmailChange(validUser, TOKEN);

            // Assert
            assertThat(result).isEqualTo(NEW_EMAIL);
            assertThat(validUser.getEmail()).isEqualTo(NEW_EMAIL);
            verify(userRepository).save(validUser);
            verify(verificationService).deleteByUserIdAndType(validUser.getId(),
                    TokenType.EMAIL_CHANGE);
        }
    }

    // ========================================================================
    // TESTS: validateNewEmail()
    // ========================================================================

    @Nested
    @DisplayName("validateNewEmail() - Validar novo email")
    class ValidateNewEmailTests {

        @Test
        @DisplayName("Deveria lançar exceção quando novo email é igual ao atual (case-insensitive)")
        void shouldThrowException_WhenNewEmailIsSameAsCurrent() {
            // Act & Assert
            assertThatThrownBy(() -> userService.validateNewEmail(validUser, EMAIL))
                    .isInstanceOf(EmailAlreadyTakenException.class)
                    .hasMessage("Este já é seu email atual");

            assertThatThrownBy(() -> userService.validateNewEmail(validUser, EMAIL.toUpperCase()))
                    .isInstanceOf(EmailAlreadyTakenException.class)
                    .hasMessage("Este já é seu email atual");
        }

        @Test
        @DisplayName("Deveria lançar exceção quando email já está verificado por outro usuário")
        void shouldThrowException_WhenEmailIsAlreadyVerifiedByAnotherUser() {
            // Arrange
            when(userRepository.existsByEmailAndVerified(NEW_EMAIL)).thenReturn(true);

            // Act & Assert
            assertThatThrownBy(() -> userService.validateNewEmail(validUser, NEW_EMAIL))
                    .isInstanceOf(EmailAlreadyTakenException.class)
                    .hasMessage("Email já está em uso");
        }

        @Test
        @DisplayName("Deveria passar validação quando novo email é válido")
        void shouldPassValidation_WhenNewEmailIsValid() {
            // Arrange
            when(userRepository.existsByEmailAndVerified(NEW_EMAIL)).thenReturn(false);

            // Act & Assert - não deve lançar exceção
            org.junit.jupiter.api.Assertions
                    .assertDoesNotThrow(() -> userService.validateNewEmail(validUser, NEW_EMAIL));
        }
    }

    // ========================================================================
    // TESTS: loadByUsername()
    // ========================================================================

    @Nested
    @DisplayName("loadByUsername() - Carregar usuário por username")
    class LoadByUsernameTests {

        @Test
        @DisplayName("Deveria retornar usuário quando username existe")
        void shouldReturnUser_WhenUsernameExists() {
            // Arrange
            when(userRepository.findByUsername(USERNAME)).thenReturn(Optional.of(validUser));

            // Act
            User result = userService.loadByUsername(USERNAME);

            // Assert
            assertThat(result).isNotNull().isEqualTo(validUser);
            verify(userRepository).findByUsername(USERNAME);
        }

        @Test
        @DisplayName("Deveria lançar UsernameNotFoundException quando username não existe")
        void shouldThrowUsernameNotFoundException_WhenUsernameDoesNotExist() {
            // Arrange
            when(userRepository.findByUsername(USERNAME)).thenReturn(Optional.empty());

            // Act & Assert
            assertThatThrownBy(() -> userService.loadByUsername(USERNAME))
                    .isInstanceOf(UsernameNotFoundException.class)
                    .hasMessageContaining("User not found: " + USERNAME);

            verify(userRepository).findByUsername(USERNAME);
        }
    }

    // ========================================================================
    // TESTS: Utility methods
    // ========================================================================

    @Nested
    @DisplayName("Métodos utilitários")
    class UtilityMethodsTests {

        @Test
        @DisplayName("existsByUsername() - Deveria retornar true quando username existe")
        void existsByUsername_ShouldReturnTrue_WhenUsernameExists() {
            // Arrange
            when(userRepository.existsByUsername(USERNAME)).thenReturn(true);

            // Act
            boolean result = userService.existsByUsername(USERNAME);

            // Assert
            assertThat(result).isTrue();
            verify(userRepository).existsByUsername(USERNAME);
        }

        @Test
        @DisplayName("existsByEmail() - Deveria retornar true quando email existe")
        void existsByEmail_ShouldReturnTrue_WhenEmailExists() {
            // Arrange
            when(userRepository.existsByEmail(EMAIL)).thenReturn(true);

            // Act
            boolean result = userService.existsByEmail(EMAIL);

            // Assert
            assertThat(result).isTrue();
            verify(userRepository).existsByEmail(EMAIL);
        }

        @Test
        @DisplayName("findByEmail() - Deveria retornar usuário quando email existe")
        void findByEmail_ShouldReturnUser_WhenEmailExists() {
            // Arrange
            when(userRepository.findByEmail(EMAIL)).thenReturn(Optional.of(validUser));

            // Act
            User result = userService.findByEmail(EMAIL);

            // Assert
            assertThat(result).isNotNull().isEqualTo(validUser);
            verify(userRepository).findByEmail(EMAIL);
        }

        @Test
        @DisplayName("findByEmail() - Deveria lançar exceção quando email não existe")
        void findByEmail_ShouldThrowException_WhenEmailDoesNotExist() {
            // Arrange
            when(userRepository.findByEmail(EMAIL)).thenReturn(Optional.empty());

            // Act & Assert
            assertThatThrownBy(() -> userService.findByEmail(EMAIL))
                    .isInstanceOf(UserNotFoundException.class)
                    .hasMessageContaining("User not found: " + EMAIL);
        }

        @Test
        @DisplayName("updateEmail() - Deveria atualizar email e salvar usuário")
        void updateEmail_ShouldUpdateEmailAndSaveUser() {
            // Arrange
            when(userRepository.save(validUser)).thenReturn(validUser);

            // Act
            userService.updateEmail(validUser, NEW_EMAIL);

            // Assert
            assertThat(validUser.getEmail()).isEqualTo(NEW_EMAIL);
            verify(userRepository).save(validUser);
        }

        @Test
        @DisplayName("cleanupExpiredUnverifiedUsers() - Deveria chamar repositório com data correta")
        void cleanupExpiredUnverifiedUsers_ShouldCallRepositoryWithCorrectDate() {
            // Arrange
            int daysToExpire = 7;
            when(userRepository.deleteExpiredUnverifiedUsers(any(LocalDateTime.class)))
                    .thenReturn(5);

            // Act
            int result = userService.cleanupExpiredUnverifiedUsers(daysToExpire);

            // Assert
            assertThat(result).isEqualTo(5);
            verify(userRepository).deleteExpiredUnverifiedUsers(any(LocalDateTime.class));
        }
    }
}
