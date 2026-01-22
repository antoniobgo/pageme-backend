package com.atwo.paganois.services;

import com.atwo.paganois.dtos.UserDTO;
import com.atwo.paganois.entities.Role;
import com.atwo.paganois.entities.User;
import com.atwo.paganois.exceptions.AccountDisabledException;
import com.atwo.paganois.exceptions.UserNotFoundException;
import com.atwo.paganois.repositories.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

/**
 * Testes unitários para CustomUserDetailsService
 * 
 * Esta classe testa:
 * 1. Métodos de busca (findByEmail)
 * 2. Métodos de verificação (existsByUsername, existsByEmail)
 * 3. Método de salvamento (save)
 * 4. Método de perfil autenticado (getAuthenticatedUserProfile)
 * 5. Implementação do UserDetailsService (loadUserByUsername)
 */
@ExtendWith(MockitoExtension.class)
@DisplayName("CustomUserDetailsService - Testes Unitários")
class CustomUserDetailsServiceTest {

    @Mock
    private UserRepository userRepository;

    @InjectMocks
    private CustomUserDetailsService userDetailsService;

    private User validUser;
    private Role userRole;

    @BeforeEach
    void setUp() {
        // Cria Role para os testes
        userRole = new Role();
        userRole.setId(1L);
        userRole.setAuthority("ROLE_USER");

        // Cria User válido para os testes
        validUser = new User();
        validUser.setId(1L);
        validUser.setUsername("testuser");
        validUser.setEmail("test@example.com");
        validUser.setPassword("encodedPassword123");
        validUser.setRole(userRole);
        validUser.setEnabled(true);
        validUser.setEmailVerified(true);
    }

    // ========================================================================
    // TESTES: findByEmail()
    // ========================================================================

    @Nested
    @DisplayName("findByEmail() - Buscar usuário por email")
    class FindByEmailTests {

        @Test
        @DisplayName("Deveria retornar Optional com usuário quando email existe")
        void shouldReturnUser_WhenEmailExists() {
            // Arrange
            when(userRepository.findByEmail("test@example.com"))
                    .thenReturn(Optional.of(validUser));

            // Act
            Optional<User> result = userDetailsService.findByEmail("test@example.com");

            // Assert
            assertThat(result).isPresent();
            assertThat(result.get().getEmail()).isEqualTo("test@example.com");
            verify(userRepository, times(1)).findByEmail("test@example.com");
        }

        @Test
        @DisplayName("Deveria retornar Optional vazio quando email não existe")
        void shouldReturnEmpty_WhenEmailDoesNotExist() {
            // Arrange
            when(userRepository.findByEmail("naoexiste@example.com"))
                    .thenReturn(Optional.empty());

            // Act
            Optional<User> result = userDetailsService.findByEmail("naoexiste@example.com");

            // Assert
            assertThat(result).isEmpty();
            verify(userRepository, times(1)).findByEmail("naoexiste@example.com");
        }

        @Test
        @DisplayName("Deveria delegar chamada ao repository")
        void shouldDelegateCall_ToRepository() {
            // Arrange
            String email = "any@email.com";

            // Act
            userDetailsService.findByEmail(email);

            // Assert
            verify(userRepository, times(1)).findByEmail(email);
        }
    }

    // ========================================================================
    // TESTES: save()
    // ========================================================================

    @Nested
    @DisplayName("save() - Salvar usuário")
    class SaveTests {

        @Test
        @DisplayName("Deveria salvar usuário e retornar usuário salvo")
        void shouldSaveUser_AndReturnSavedUser() {
            // Arrange
            when(userRepository.save(validUser)).thenReturn(validUser);

            // Act
            User savedUser = userDetailsService.save(validUser);

            // Assert
            assertThat(savedUser).isNotNull();
            assertThat(savedUser.getId()).isEqualTo(1L);
            assertThat(savedUser.getUsername()).isEqualTo("testuser");
            verify(userRepository, times(1)).save(validUser);
        }

        @Test
        @DisplayName("Deveria retornar usuário com ID após salvar novo usuário")
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
            User result = userDetailsService.save(newUser);

            // Assert
            assertThat(result.getId()).isEqualTo(2L);
            verify(userRepository, times(1)).save(newUser);
        }
    }

    // ========================================================================
    // TESTES: existsByUsername()
    // ========================================================================

    @Nested
    @DisplayName("existsByUsername() - Verificar se username existe")
    class ExistsByUsernameTests {

        @Test
        @DisplayName("Deveria retornar true quando username existe")
        void shouldReturnTrue_WhenUsernameExists() {
            // Arrange
            when(userRepository.existsByUsername("testuser")).thenReturn(true);

            // Act
            boolean exists = userDetailsService.existsByUsername("testuser");

            // Assert
            assertThat(exists).isTrue();
            verify(userRepository, times(1)).existsByUsername("testuser");
        }

        @Test
        @DisplayName("Deveria retornar false quando username não existe")
        void shouldReturnFalse_WhenUsernameDoesNotExist() {
            // Arrange
            when(userRepository.existsByUsername("naoexiste")).thenReturn(false);

            // Act
            boolean exists = userDetailsService.existsByUsername("naoexiste");

            // Assert
            assertThat(exists).isFalse();
            verify(userRepository, times(1)).existsByUsername("naoexiste");
        }
    }

    // ========================================================================
    // TESTES: existsByEmail()
    // ========================================================================

    @Nested
    @DisplayName("existsByEmail() - Verificar se email existe")
    class ExistsByEmailTests {

        @Test
        @DisplayName("Deveria retornar true quando email existe")
        void shouldReturnTrue_WhenEmailExists() {
            // Arrange
            when(userRepository.existsByEmail("test@example.com")).thenReturn(true);

            // Act
            boolean exists = userDetailsService.existsByEmail("test@example.com");

            // Assert
            assertThat(exists).isTrue();
            verify(userRepository, times(1)).existsByEmail("test@example.com");
        }

        @Test
        @DisplayName("Deveria retornar false quando email não existe")
        void shouldReturnFalse_WhenEmailDoesNotExist() {
            // Arrange
            when(userRepository.existsByEmail("naoexiste@example.com")).thenReturn(false);

            // Act
            boolean exists = userDetailsService.existsByEmail("naoexiste@example.com");

            // Assert
            assertThat(exists).isFalse();
            verify(userRepository, times(1)).existsByEmail("naoexiste@example.com");
        }
    }

    // ========================================================================
    // TESTES: getAuthenticatedUserProfile()
    // ========================================================================

    @Nested
    @DisplayName("getAuthenticatedUserProfile() - Obter perfil do usuário autenticado")
    class GetAuthenticatedUserProfileTests {

        @Test
        @DisplayName("Deveria retornar UserDTO quando usuário está habilitado e existe")
        void shouldReturnUserDTO_WhenUserIsValidAndExists() {
            // Arrange
            when(userRepository.existsByUsername("testuser")).thenReturn(true);

            // Act
            UserDTO userDTO = userDetailsService.getAuthenticatedUserProfile(validUser);

            // Assert
            assertThat(userDTO).isNotNull();
            assertThat(userDTO.getUsername()).isEqualTo("testuser");
            verify(userRepository, times(1)).existsByUsername("testuser");
        }

        @Test
        @DisplayName("Deveria lançar AccountDisabledException quando conta está desabilitada")
        void shouldThrowAccountDisabledException_WhenAccountIsDisabled() {
            // Arrange
            validUser.setEnabled(false);

            // Act & Assert
            assertThatThrownBy(() -> userDetailsService.getAuthenticatedUserProfile(validUser))
                    .isInstanceOf(AccountDisabledException.class)
                    .hasMessage("Conta desativada");

            // Não deve nem chamar o repository
            verify(userRepository, never()).existsByUsername(any());
        }

        @Test
        @DisplayName("Deveria lançar UserNotFoundException quando usuário não existe no banco")
        void shouldThrowUserNotFoundException_WhenUserDoesNotExist() {
            // Arrange
            when(userRepository.existsByUsername("testuser")).thenReturn(false);

            // Act & Assert
            assertThatThrownBy(() -> userDetailsService.getAuthenticatedUserProfile(validUser))
                    .isInstanceOf(UserNotFoundException.class)
                    .hasMessage("Usuário não encontrado");

            verify(userRepository, times(1)).existsByUsername("testuser");
        }

        @Test
        @DisplayName("Deveria verificar enabled antes de verificar existência no banco")
        void shouldCheckEnabled_BeforeCheckingExistence() {
            // Arrange
            validUser.setEnabled(false);

            // Act & Assert
            assertThatThrownBy(() -> userDetailsService.getAuthenticatedUserProfile(validUser))
                    .isInstanceOf(AccountDisabledException.class);

            // Verifica que NÃO chamou o repository (falhou antes)
            verify(userRepository, never()).existsByUsername(any());
        }

        @Test
        @DisplayName("Deveria criar UserDTO com dados corretos do UserDetails")
        void shouldCreateUserDTO_WithCorrectUserDetailsData() {
            // Arrange
            when(userRepository.existsByUsername("testuser")).thenReturn(true);

            // Act
            UserDTO userDTO = userDetailsService.getAuthenticatedUserProfile(validUser);

            // Assert
            assertThat(userDTO.getUsername()).isEqualTo(validUser.getUsername());
            assertThat(userDTO.getRole().getAuthority()).isEqualTo(validUser.getRole().getAuthority());
        }
    }

    // ========================================================================
    // TESTES: loadUserByUsername() - Implementação de UserDetailsService
    // ========================================================================

    @Nested
    @DisplayName("loadUserByUsername() - Carregar usuário para autenticação")
    class LoadUserByUsernameTests {

        @Test
        @DisplayName("Deveria retornar User quando username existe")
        void shouldReturnUser_WhenUsernameExists() {
            // Arrange
            when(userRepository.findByUsername("testuser"))
                    .thenReturn(Optional.of(validUser));

            // Act
            User result = userDetailsService.loadUserByUsername("testuser");

            // Assert
            assertThat(result).isNotNull();
            assertThat(result.getUsername()).isEqualTo("testuser");
            assertThat(result.getEmail()).isEqualTo("test@example.com");
            verify(userRepository, times(1)).findByUsername("testuser");
        }

        @Test
        @DisplayName("Deveria lançar UsernameNotFoundException quando username não existe")
        void shouldThrowUsernameNotFoundException_WhenUsernameDoesNotExist() {
            // Arrange
            when(userRepository.findByUsername("naoexiste"))
                    .thenReturn(Optional.empty());

            // Act & Assert
            assertThatThrownBy(() -> userDetailsService.loadUserByUsername("naoexiste"))
                    .isInstanceOf(UsernameNotFoundException.class)
                    .hasMessageContaining("User not found: naoexiste");

            verify(userRepository, times(1)).findByUsername("naoexiste");
        }

        @Test
        @DisplayName("Deveria retornar User implementando UserDetails")
        void shouldReturnUser_ImplementingUserDetails() {
            // Arrange
            when(userRepository.findByUsername("testuser"))
                    .thenReturn(Optional.of(validUser));

            // Act
            User result = userDetailsService.loadUserByUsername("testuser");

            // Assert - verifica que é um UserDetails válido
            assertThat(result).isInstanceOf(UserDetails.class);
            assertThat(result.getUsername()).isNotNull();
            assertThat(result.getPassword()).isNotNull();
            assertThat(result.getAuthorities()).isNotEmpty();
        }

        @Test
        @DisplayName("Deveria incluir username na mensagem de erro quando não encontra")
        void shouldIncludeUsername_InErrorMessage_WhenNotFound() {
            // Arrange
            String username = "usuarioInexistente";
            when(userRepository.findByUsername(username))
                    .thenReturn(Optional.empty());

            // Act & Assert
            assertThatThrownBy(() -> userDetailsService.loadUserByUsername(username))
                    .isInstanceOf(UsernameNotFoundException.class)
                    .hasMessage("User not found: " + username);
        }

        @Test
        @DisplayName("Deveria retornar mesmo usuário para múltiplas chamadas com mesmo username")
        void shouldReturnSameUser_ForMultipleCalls_WithSameUsername() {
            // Arrange
            when(userRepository.findByUsername("testuser"))
                    .thenReturn(Optional.of(validUser));

            // Act
            User result1 = userDetailsService.loadUserByUsername("testuser");
            User result2 = userDetailsService.loadUserByUsername("testuser");

            // Assert
            assertThat(result1.getUsername()).isEqualTo(result2.getUsername());
            verify(userRepository, times(2)).findByUsername("testuser");
        }
    }

    // ========================================================================
    // TESTES: Cenários de integração entre métodos
    // ========================================================================

    @Nested
    @DisplayName("Cenários de integração")
    class IntegrationScenariosTests {

        @Test
        @DisplayName("Deveria salvar e depois encontrar usuário por email")
        void save_shouldSave_WhenIsAValidUser() {
            // Arrange
            when(userRepository.save(validUser)).thenReturn(validUser);
            when(userRepository.findByEmail("test@example.com"))
                    .thenReturn(Optional.of(validUser));

            // Act
            User saved = userDetailsService.save(validUser);
            Optional<User> found = userDetailsService.findByEmail("test@example.com");

            // Assert
            assertThat(found).isPresent();
            assertThat(found.get().getEmail()).isEqualTo(saved.getEmail());
        }

        @Test
        @DisplayName("Deveria verificar existência antes de tentar carregar usuário")
        void existsByUsername_shouldCheckExistence_BeforeTryingToLoadUser() {
            // Arrange
            when(userRepository.existsByUsername("testuser")).thenReturn(true);
            when(userRepository.findByUsername("testuser"))
                    .thenReturn(Optional.of(validUser));

            // Act
            boolean exists = userDetailsService.existsByUsername("testuser");
            User loaded = null;
            if (exists) {
                loaded = userDetailsService.loadUserByUsername("testuser");
            }

            // Assert
            assertThat(exists).isTrue();
            assertThat(loaded).isNotNull();
            assertThat(loaded.getUsername()).isEqualTo("testuser");
        }
    }
}