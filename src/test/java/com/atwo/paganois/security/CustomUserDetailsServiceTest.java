package com.atwo.paganois.security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import com.atwo.paganois.user.entities.Role;
import com.atwo.paganois.user.entities.User;
import com.atwo.paganois.user.repositories.UserRepository;

/**
 * Unit tests for CustomUserDetailsService
 * 
 * Structure: - loadUserByUsername() - Load user by username for Spring Security
 */
@ExtendWith(MockitoExtension.class)
@DisplayName("CustomUserDetailsService - Unit Tests")
class CustomUserDetailsServiceTest {

    @Mock
    private UserRepository userRepository;

    @InjectMocks
    private CustomUserDetailsService userDetailsService;

    private User validUser;
    private Role userRole;

    private static final String USERNAME = "testuser";
    private static final String PASSWORD = "encodedPassword";

    @BeforeEach
    void setUp() {
        userRole = new Role();
        userRole.setId(1L);
        userRole.setAuthority("ROLE_USER");

        validUser = new User();
        validUser.setId(1L);
        validUser.setUsername(USERNAME);
        validUser.setPassword(PASSWORD);
        validUser.setEmail("test@example.com");
        validUser.setRole(userRole);
        validUser.setEnabled(true);
        validUser.setEmailVerified(true);
    }

    @Test
    @DisplayName("Deveria retornar usuário quando username existe")
    void shouldReturnUser_WhenUsernameExists() {
        // Arrange
        when(userRepository.findByUsername(USERNAME)).thenReturn(Optional.of(validUser));

        // Act
        User result = userDetailsService.loadUserByUsername(USERNAME);

        // Assert
        assertThat(result).isNotNull().isEqualTo(validUser);
        assertThat(result.getUsername()).isEqualTo(USERNAME);
        verify(userRepository).findByUsername(USERNAME);
    }

    @Test
    @DisplayName("Deveria lançar UsernameNotFoundException quando username não existe")
    void shouldThrowUsernameNotFoundException_WhenUsernameNotFound() {
        // Arrange
        String nonExistentUsername = "nonexistent";
        when(userRepository.findByUsername(nonExistentUsername)).thenReturn(Optional.empty());

        // Act & Assert
        assertThatThrownBy(() -> userDetailsService.loadUserByUsername(nonExistentUsername))
                .isInstanceOf(UsernameNotFoundException.class)
                .hasMessageContaining("User not found: " + nonExistentUsername);

        verify(userRepository).findByUsername(nonExistentUsername);
    }

    @Test
    @DisplayName("Deveria retornar usuário com todas as propriedades preenchidas")
    void shouldReturnUser_WithAllProperties() {
        // Arrange
        when(userRepository.findByUsername(USERNAME)).thenReturn(Optional.of(validUser));

        // Act
        User result = userDetailsService.loadUserByUsername(USERNAME);

        // Assert
        assertThat(result.getId()).isEqualTo(1L);
        assertThat(result.getUsername()).isEqualTo(USERNAME);
        assertThat(result.getPassword()).isEqualTo(PASSWORD);
        assertThat(result.getEmail()).isEqualTo("test@example.com");
        assertThat(result.getRole()).isEqualTo(userRole);
        assertThat(result.isEnabled()).isTrue();
        assertThat(result.isEmailVerified()).isTrue();
    }

    @Test
    @DisplayName("Deveria delegar busca para o repositório")
    void shouldDelegateSearch_ToRepository() {
        // Arrange
        when(userRepository.findByUsername(USERNAME)).thenReturn(Optional.of(validUser));

        // Act
        userDetailsService.loadUserByUsername(USERNAME);

        // Assert
        verify(userRepository).findByUsername(USERNAME);
    }

    @Test
    @DisplayName("Deveria funcionar com diferentes usernames")
    void shouldWork_WithDifferentUsernames() {
        // Arrange
        String username1 = "user1";
        String username2 = "user2";

        User user1 = new User();
        user1.setUsername(username1);

        User user2 = new User();
        user2.setUsername(username2);

        when(userRepository.findByUsername(username1)).thenReturn(Optional.of(user1));
        when(userRepository.findByUsername(username2)).thenReturn(Optional.of(user2));

        // Act
        User result1 = userDetailsService.loadUserByUsername(username1);
        User result2 = userDetailsService.loadUserByUsername(username2);

        // Assert
        assertThat(result1.getUsername()).isEqualTo(username1);
        assertThat(result2.getUsername()).isEqualTo(username2);
    }
}
