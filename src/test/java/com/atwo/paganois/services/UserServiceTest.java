package com.atwo.paganois.services;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import com.atwo.paganois.dtos.UserDTO;
import com.atwo.paganois.entities.Role;
import com.atwo.paganois.entities.User;
import com.atwo.paganois.exceptions.AccountDisabledException;
import com.atwo.paganois.exceptions.UserNotFoundException;
import com.atwo.paganois.repositories.RoleRepository;
import com.atwo.paganois.repositories.UserRepository;

/**
 * Unit tests for UserService
 * 
 * Tests cover:
 * 1. User persistence operations
 * 2. User profile retrieval with validation
 * 3. User registration
 * 4. Password update operations
 */
@ExtendWith(MockitoExtension.class)
@DisplayName("UserService - Unit Tests")
class UserServiceTest {

    @Mock
    private UserRepository userRepository;

    @Mock
    private RoleRepository roleRepository;

    @InjectMocks
    private UserService userService;

    private User validUser;
    private Role userRole;

    private static final String USERNAME = "testuser";
    private static final String EMAIL = "test@example.com";
    private static final String PASSWORD = "password123";
    private static final String ENCODED_PASSWORD = "encodedPassword123";
    private static final String NEW_ENCODED_PASSWORD = "newEncodedPassword456";

    @BeforeEach
    void setUp() {
        // Setup Role
        userRole = new Role();
        userRole.setId(1L);
        userRole.setAuthority("ROLE_USER");

        // Setup valid User
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
    @DisplayName("save() - Save user to repository")
    class SaveTests {

        @Test
        @DisplayName("Should save user and return saved user")
        void shouldSaveUser_AndReturnSavedUser() {
            // Arrange
            when(userRepository.save(validUser)).thenReturn(validUser);

            // Act
            User result = userService.save(validUser);

            // Assert
            assertThat(result).isNotNull();
            assertThat(result).isEqualTo(validUser);
            verify(userRepository, times(1)).save(validUser);
        }

        @Test
        @DisplayName("Should delegate save operation to repository")
        void shouldDelegateSaveOperation_ToRepository() {
            // Arrange
            when(userRepository.save(validUser)).thenReturn(validUser);

            // Act
            userService.save(validUser);

            // Assert
            verify(userRepository, times(1)).save(validUser);
        }

        @Test
        @DisplayName("Should return user with ID after saving new user")
        void shouldReturnUserWithId_AfterSavingNewUser() {
            // Arrange
            User newUser = new User();
            newUser.setUsername("newuser");
            newUser.setEmail("new@example.com");

            User savedUser = new User();
            savedUser.setId(2L);
            savedUser.setUsername("newuser");
            savedUser.setEmail("new@example.com");

            when(userRepository.save(newUser)).thenReturn(savedUser);

            // Act
            User result = userService.save(newUser);

            // Assert
            assertThat(result.getId()).isNotNull();
            assertThat(result.getId()).isEqualTo(2L);
            verify(userRepository, times(1)).save(newUser);
        }

        @Test
        @DisplayName("Should save user with all properties")
        void shouldSaveUser_WithAllProperties() {
            // Arrange
            ArgumentCaptor<User> userCaptor = ArgumentCaptor.forClass(User.class);
            when(userRepository.save(any(User.class))).thenReturn(validUser);

            // Act
            userService.save(validUser);

            // Assert
            verify(userRepository).save(userCaptor.capture());
            User capturedUser = userCaptor.getValue();

            assertThat(capturedUser.getUsername()).isEqualTo(USERNAME);
            assertThat(capturedUser.getEmail()).isEqualTo(EMAIL);
            assertThat(capturedUser.getPassword()).isEqualTo(ENCODED_PASSWORD);
            assertThat(capturedUser.getRole()).isEqualTo(userRole);
        }
    }

    // ========================================================================
    // TESTS: getAuthenticatedUserProfile()
    // ========================================================================

    @Nested
    @DisplayName("getAuthenticatedUserProfile() - Get profile of authenticated user")
    class GetAuthenticatedUserProfileTests {

        @Test
        @DisplayName("Should return UserDTO when user is enabled and exists")
        void shouldReturnUserDTO_WhenUserEnabledAndExists() {
            // Arrange
            when(userRepository.existsByUsername(USERNAME)).thenReturn(true);

            // Act
            UserDTO result = userService.getAuthenticatedUserProfile(validUser);

            // Assert
            assertThat(result).isNotNull();
            assertThat(result.getUsername()).isEqualTo(USERNAME);
            verify(userRepository, times(1)).existsByUsername(USERNAME);
        }

        @Test
        @DisplayName("Should throw AccountDisabledException when user is disabled")
        void shouldThrowAccountDisabledException_WhenUserDisabled() {
            // Arrange
            validUser.setEnabled(false);

            // Act & Assert
            assertThatThrownBy(() -> userService.getAuthenticatedUserProfile(validUser))
                    .isInstanceOf(AccountDisabledException.class)
                    .hasMessage("Conta desativada");

            // Should not check repository (early return)
            verify(userRepository, never()).existsByUsername(any());
        }

        @Test
        @DisplayName("Should throw UserNotFoundException when user does not exist in repository")
        void shouldThrowUserNotFoundException_WhenUserNotInRepository() {
            // Arrange
            when(userRepository.existsByUsername(USERNAME)).thenReturn(false);

            // Act & Assert
            assertThatThrownBy(() -> userService.getAuthenticatedUserProfile(validUser))
                    .isInstanceOf(UserNotFoundException.class)
                    .hasMessage("Usuário não encontrado");

            verify(userRepository, times(1)).existsByUsername(USERNAME);
        }

        @Test
        @DisplayName("Should check if user is enabled before checking existence")
        void shouldCheckEnabled_BeforeCheckingExistence() {
            // Arrange
            validUser.setEnabled(false);

            // Act & Assert
            assertThatThrownBy(() -> userService.getAuthenticatedUserProfile(validUser))
                    .isInstanceOf(AccountDisabledException.class);

            // Verify repository was NOT called (failed before)
            verify(userRepository, never()).existsByUsername(any());
        }

        @Test
        @DisplayName("Should create UserDTO with correct user details")
        void shouldCreateUserDTO_WithCorrectDetails() {
            // Arrange
            when(userRepository.existsByUsername(USERNAME)).thenReturn(true);

            // Act
            UserDTO result = userService.getAuthenticatedUserProfile(validUser);

            // Assert
            assertThat(result.getUsername()).isEqualTo(validUser.getUsername());
            assertThat(result.getRole().getAuthority()).isEqualTo(validUser.getRole().getAuthority());
        }

    }

    // ========================================================================
    // TESTS: registerUser()
    // ========================================================================

    @Nested
    @DisplayName("registerUser() - Register new user")
    class RegisterUserTests {

        @Test
        @DisplayName("Should create user with provided details")
        void shouldCreateUser_WithProvidedDetails() {
            // Arrange
            when(roleRepository.findByAuthority("ROLE_USER")).thenReturn(userRole);
            when(userRepository.save(any(User.class))).thenReturn(validUser);

            ArgumentCaptor<User> userCaptor = ArgumentCaptor.forClass(User.class);

            // Act
            userService.registerUser(USERNAME, ENCODED_PASSWORD, EMAIL);

            // Assert
            verify(userRepository).save(userCaptor.capture());
            User capturedUser = userCaptor.getValue();

            assertThat(capturedUser.getUsername()).isEqualTo(USERNAME);
            assertThat(capturedUser.getPassword()).isEqualTo(ENCODED_PASSWORD);
            assertThat(capturedUser.getEmail()).isEqualTo(EMAIL);
        }

        @Test
        @DisplayName("Should assign ROLE_USER to new user")
        void shouldAssignRoleUser_ToNewUser() {
            // Arrange
            when(roleRepository.findByAuthority("ROLE_USER")).thenReturn(userRole);
            when(userRepository.save(any(User.class))).thenReturn(validUser);

            ArgumentCaptor<User> userCaptor = ArgumentCaptor.forClass(User.class);

            // Act
            userService.registerUser(USERNAME, ENCODED_PASSWORD, EMAIL);

            // Assert
            verify(roleRepository, times(1)).findByAuthority("ROLE_USER");
            verify(userRepository).save(userCaptor.capture());
            assertThat(userCaptor.getValue().getRole()).isEqualTo(userRole);
        }

        @Test
        @DisplayName("Should save user and return saved user")
        void shouldSaveUser_AndReturnSavedUser() {
            // Arrange
            when(roleRepository.findByAuthority("ROLE_USER")).thenReturn(userRole);
            when(userRepository.save(any(User.class))).thenReturn(validUser);

            // Act
            User result = userService.registerUser(USERNAME, ENCODED_PASSWORD, EMAIL);

            // Assert
            assertThat(result).isNotNull();
            assertThat(result).isEqualTo(validUser);
            verify(userRepository, times(1)).save(any(User.class));
        }

        @Test
        @DisplayName("Should accept already encoded password")
        void shouldAcceptAlreadyEncodedPassword() {
            // Arrange
            String encodedPwd = "$2a$10$abcdefghijklmnopqrstuvwxyz";
            when(roleRepository.findByAuthority("ROLE_USER")).thenReturn(userRole);
            when(userRepository.save(any(User.class))).thenReturn(validUser);

            ArgumentCaptor<User> userCaptor = ArgumentCaptor.forClass(User.class);

            // Act
            userService.registerUser(USERNAME, encodedPwd, EMAIL);

            // Assert
            verify(userRepository).save(userCaptor.capture());
            assertThat(userCaptor.getValue().getPassword()).isEqualTo(encodedPwd);
        }

        @Test
        @DisplayName("Should set all user properties correctly")
        void shouldSetAllUserProperties_Correctly() {
            // Arrange
            when(roleRepository.findByAuthority("ROLE_USER")).thenReturn(userRole);
            when(userRepository.save(any(User.class))).thenReturn(validUser);

            ArgumentCaptor<User> userCaptor = ArgumentCaptor.forClass(User.class);

            // Act
            userService.registerUser(USERNAME, ENCODED_PASSWORD, EMAIL);

            // Assert
            verify(userRepository).save(userCaptor.capture());
            User capturedUser = userCaptor.getValue();

            assertThat(capturedUser.getUsername()).isEqualTo(USERNAME);
            assertThat(capturedUser.getPassword()).isEqualTo(ENCODED_PASSWORD);
            assertThat(capturedUser.getEmail()).isEqualTo(EMAIL);
            assertThat(capturedUser.getRole()).isEqualTo(userRole);
        }

        @Test
        @DisplayName("Should fetch ROLE_USER from repository")
        void shouldFetchRoleUser_FromRepository() {
            // Arrange
            when(roleRepository.findByAuthority("ROLE_USER")).thenReturn(userRole);
            when(userRepository.save(any(User.class))).thenReturn(validUser);

            ArgumentCaptor<String> roleNameCaptor = ArgumentCaptor.forClass(String.class);

            // Act
            userService.registerUser(USERNAME, ENCODED_PASSWORD, EMAIL);

            // Assert
            verify(roleRepository).findByAuthority(roleNameCaptor.capture());
            assertThat(roleNameCaptor.getValue()).isEqualTo("ROLE_USER");
        }
    }

    // ========================================================================
    // TESTS: setNewPassword()
    // ========================================================================

    @Nested
    @DisplayName("setNewPassword() - Update user password")
    class SetNewPasswordTests {

        @Test
        @DisplayName("Should update user password with encoded password")
        void shouldUpdateUserPassword_WithEncodedPassword() {
            // Arrange
            String oldPassword = validUser.getPassword();
            when(userRepository.save(validUser)).thenReturn(validUser);

            // Act
            userService.setNewPassword(validUser, NEW_ENCODED_PASSWORD);

            // Assert
            assertThat(validUser.getPassword()).isEqualTo(NEW_ENCODED_PASSWORD);
            assertThat(validUser.getPassword()).isNotEqualTo(oldPassword);
        }

        @Test
        @DisplayName("Should save user after updating password")
        void shouldSaveUser_AfterUpdatingPassword() {
            // Arrange
            when(userRepository.save(validUser)).thenReturn(validUser);

            // Act
            userService.setNewPassword(validUser, NEW_ENCODED_PASSWORD);

            // Assert
            verify(userRepository, times(1)).save(validUser);
        }

        @Test
        @DisplayName("Should set password before saving user")
        void shouldSetPassword_BeforeSavingUser() {
            // Arrange
            ArgumentCaptor<User> userCaptor = ArgumentCaptor.forClass(User.class);
            when(userRepository.save(any(User.class))).thenReturn(validUser);

            // Act
            userService.setNewPassword(validUser, NEW_ENCODED_PASSWORD);

            // Assert
            verify(userRepository).save(userCaptor.capture());
            assertThat(userCaptor.getValue().getPassword()).isEqualTo(NEW_ENCODED_PASSWORD);
        }

        @Test
        @DisplayName("Should accept already encoded new password")
        void shouldAcceptAlreadyEncodedNewPassword() {
            // Arrange
            String bcryptPassword = "$2a$10$newEncodedPasswordHash";
            when(userRepository.save(validUser)).thenReturn(validUser);

            ArgumentCaptor<User> userCaptor = ArgumentCaptor.forClass(User.class);

            // Act
            userService.setNewPassword(validUser, bcryptPassword);

            // Assert
            verify(userRepository).save(userCaptor.capture());
            assertThat(userCaptor.getValue().getPassword()).isEqualTo(bcryptPassword);
        }

        @Test
        @DisplayName("Should modify the same user instance")
        void shouldModifySameUserInstance() {
            // Arrange
            when(userRepository.save(validUser)).thenReturn(validUser);

            // Act
            userService.setNewPassword(validUser, NEW_ENCODED_PASSWORD);

            // Assert
            verify(userRepository).save(validUser); // Same instance
            assertThat(validUser.getPassword()).isEqualTo(NEW_ENCODED_PASSWORD);
        }

        @Test
        @DisplayName("Should update password for any user")
        void shouldUpdatePassword_ForAnyUser() {
            // Arrange
            User anotherUser = new User();
            anotherUser.setId(2L);
            anotherUser.setUsername("anotheruser");
            anotherUser.setPassword("oldPassword");

            when(userRepository.save(anotherUser)).thenReturn(anotherUser);

            // Act
            userService.setNewPassword(anotherUser, NEW_ENCODED_PASSWORD);

            // Assert
            assertThat(anotherUser.getPassword()).isEqualTo(NEW_ENCODED_PASSWORD);
            verify(userRepository, times(1)).save(anotherUser);
        }
    }

    // ========================================================================
    // TESTS: Integration scenarios
    // ========================================================================

    @Nested
    @DisplayName("Integration scenarios")
    class IntegrationTests {

        @Test
        @DisplayName("Should complete full user registration and profile retrieval flow")
        void shouldCompleteFullRegistrationAndProfileFlow() {
            // Arrange
            when(roleRepository.findByAuthority("ROLE_USER")).thenReturn(userRole);
            when(userRepository.save(any(User.class))).thenReturn(validUser);
            when(userRepository.existsByUsername(USERNAME)).thenReturn(true);

            // Act 1: Register user
            User registeredUser = userService.registerUser(USERNAME, ENCODED_PASSWORD, EMAIL);

            // Act 2: Get profile
            UserDTO profile = userService.getAuthenticatedUserProfile(registeredUser);

            // Assert
            assertThat(registeredUser).isNotNull();
            assertThat(profile).isNotNull();
            assertThat(profile.getUsername()).isEqualTo(registeredUser.getUsername());

            verify(roleRepository).findByAuthority("ROLE_USER");
            verify(userRepository).save(any(User.class));
            verify(userRepository).existsByUsername(USERNAME);
        }

        @Test
        @DisplayName("Should complete password change flow")
        void shouldCompletePasswordChangeFlow() {
            // Arrange
            when(userRepository.save(validUser)).thenReturn(validUser);
            String originalPassword = validUser.getPassword();

            // Act
            userService.setNewPassword(validUser, NEW_ENCODED_PASSWORD);

            // Assert
            assertThat(validUser.getPassword()).isNotEqualTo(originalPassword);
            assertThat(validUser.getPassword()).isEqualTo(NEW_ENCODED_PASSWORD);
            verify(userRepository).save(validUser);
        }

        @Test
        @DisplayName("Should handle multiple password changes")
        void shouldHandleMultiplePasswordChanges() {
            // Arrange
            when(userRepository.save(validUser)).thenReturn(validUser);
            String firstNewPassword = "firstNewPassword";
            String secondNewPassword = "secondNewPassword";

            // Act
            userService.setNewPassword(validUser, firstNewPassword);
            userService.setNewPassword(validUser, secondNewPassword);

            // Assert
            assertThat(validUser.getPassword()).isEqualTo(secondNewPassword);
            verify(userRepository, times(2)).save(validUser);
        }

        @Test
        @DisplayName("Should not allow profile access for disabled user")
        void shouldNotAllowProfileAccess_ForDisabledUser() {
            // Arrange
            when(roleRepository.findByAuthority("ROLE_USER")).thenReturn(userRole);

            User disabledUser = new User();
            disabledUser.setUsername(USERNAME);
            disabledUser.setEnabled(false);

            when(userRepository.save(any(User.class))).thenReturn(disabledUser);

            // Act
            User registeredUser = userService.registerUser(USERNAME, ENCODED_PASSWORD, EMAIL);

            // Assert - should throw when trying to get profile
            assertThatThrownBy(() -> userService.getAuthenticatedUserProfile(registeredUser))
                    .isInstanceOf(AccountDisabledException.class);
        }

        @Test
        @DisplayName("Should register user and immediately allow profile access")
        void shouldRegisterUser_AndAllowProfileAccess() {
            // Arrange
            when(roleRepository.findByAuthority("ROLE_USER")).thenReturn(userRole);
            when(userRepository.save(any(User.class))).thenReturn(validUser);
            when(userRepository.existsByUsername(USERNAME)).thenReturn(true);

            // Act
            User newUser = userService.registerUser(USERNAME, ENCODED_PASSWORD, EMAIL);
            UserDTO profile = userService.getAuthenticatedUserProfile(newUser);

            // Assert
            assertThat(newUser).isNotNull();
            assertThat(profile).isNotNull();
            assertThat(profile.getUsername()).isEqualTo(USERNAME);
        }
    }
}