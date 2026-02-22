package com.atwo.paganois.auth.controllers;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.patch;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import com.atwo.paganois.auth.entities.TokenType;
import com.atwo.paganois.auth.entities.VerificationToken;
import com.atwo.paganois.auth.repositories.VerificationTokenRepository;
import com.atwo.paganois.security.JwtUtil;
import com.atwo.paganois.user.entities.Role;
import com.atwo.paganois.user.entities.User;
import com.atwo.paganois.user.repositories.RoleRepository;
import com.atwo.paganois.user.repositories.UserRepository;
import com.fasterxml.jackson.databind.ObjectMapper;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
@DisplayName("AuthController - Integration Tests")
class AuthControllerIntegrationTest {

    @Autowired
    private MockMvc mockMvc;
    @Autowired
    private ObjectMapper objectMapper;
    @Autowired
    private UserRepository userRepository;
    @Autowired
    private RoleRepository roleRepository;
    @Autowired
    private VerificationTokenRepository tokenRepository;
    @Autowired
    private PasswordEncoder passwordEncoder;
    @Autowired
    private JwtUtil jwtUtil;

    private Role userRole;

    @BeforeEach
    void setUp() {
        userRole = roleRepository.findByAuthority("ROLE_USER");
        if (userRole == null) {
            userRole = new Role();
            userRole.setAuthority("ROLE_USER");
            userRole = roleRepository.save(userRole);
        }
    }

    @AfterEach
    void cleanup() {
        tokenRepository.deleteAll();
        userRepository.deleteAll();
    }

    private User createVerifiedUser(String username, String email, String rawPassword) {
        User user = new User();
        user.setUsername(username);
        user.setEmail(email);
        user.setPassword(passwordEncoder.encode(rawPassword));
        user.setRole(userRole);
        user.setEnabled(true);
        user.setEmailVerified(true);
        return userRepository.save(user);
    }

    private User createUnverifiedUser(String username, String email, String rawPassword) {
        User user = new User();
        user.setUsername(username);
        user.setEmail(email);
        user.setPassword(passwordEncoder.encode(rawPassword));
        user.setRole(userRole);
        user.setEnabled(true);
        user.setEmailVerified(false);
        return userRepository.save(user);
    }

    @Nested
    @DisplayName("POST /auth/register")
    class RegisterTests {
        @Test
        @DisplayName("Deveria registrar novo usuário com sucesso")
        void shouldRegisterNewUser() throws Exception {
            String json = """
                    {"username":"newuser","email":"new@example.com","password":"StrongP@ss123"}
                    """;

            mockMvc.perform(
                    post("/auth/register").contentType(MediaType.APPLICATION_JSON).content(json))
                    .andExpect(status().isCreated())
                    .andExpect(jsonPath("$.username").value("newuser"))
                    .andExpect(jsonPath("$.isEmailVerified").value(false));

            User saved = userRepository.findByUsername("newuser").orElseThrow();
            assertThat(saved.getEmail()).isEqualTo("new@example.com");
            assertThat(saved.isEmailVerified()).isFalse();
        }

        @Test
        @DisplayName("Deveria retornar 409 quando username já existe")
        void shouldReturn409_WhenUsernameExists() throws Exception {
            createVerifiedUser("existing", "test@example.com", "pass");

            String json = """
                    {"username":"existing","email":"other@example.com","password":"StrongP@ss123"}
                    """;

            mockMvc.perform(
                    post("/auth/register").contentType(MediaType.APPLICATION_JSON).content(json))
                    .andExpect(status().isConflict());
        }
    }

    @Nested
    @DisplayName("POST /auth/login")
    class LoginTests {
        @Test
        @DisplayName("Deveria fazer login com usuário verificado")
        void shouldLogin_WithVerifiedUser() throws Exception {
            createVerifiedUser("testuser", "test@example.com", "password123");

            String json = """
                    {"username":"testuser","password":"password123"}
                    """;

            mockMvc.perform(
                    post("/auth/login").contentType(MediaType.APPLICATION_JSON).content(json))
                    .andExpect(status().isOk()).andExpect(jsonPath("$.accessToken").exists())
                    .andExpect(jsonPath("$.refreshToken").exists())
                    .andExpect(jsonPath("$.tokenType").value("Bearer"));
        }

        @Test
        @DisplayName("Deveria retornar 403 quando email não verificado")
        void shouldReturn403_WhenEmailNotVerified() throws Exception {
            createUnverifiedUser("unverified", "unv@example.com", "password");

            String json = """
                    {"username":"unverified","password":"password"}
                    """;

            mockMvc.perform(
                    post("/auth/login").contentType(MediaType.APPLICATION_JSON).content(json))
                    .andExpect(status().isForbidden());
        }

        @Test
        @DisplayName("Deveria retornar 401 com senha incorreta")
        void shouldReturn401_WithWrongPassword() throws Exception {
            createVerifiedUser("testuser", "test@example.com", "correct");

            String json = """
                    {"username":"testuser","password":"wrong"}
                    """;

            mockMvc.perform(
                    post("/auth/login").contentType(MediaType.APPLICATION_JSON).content(json))
                    .andExpect(status().isUnauthorized());
        }
    }

    @Nested
    @DisplayName("POST /auth/refresh")
    class RefreshTests {
        @Test
        @DisplayName("Deveria renovar tokens com refresh válido")
        void shouldRefreshTokens() throws Exception {
            User user = createVerifiedUser("testuser", "test@example.com", "pass");
            String refreshToken = jwtUtil.generateRefreshToken(user);

            String json = String.format("""
                    {"refreshToken":"%s"}
                    """, refreshToken);

            mockMvc.perform(
                    post("/auth/refresh").contentType(MediaType.APPLICATION_JSON).content(json))
                    .andExpect(status().isOk()).andExpect(jsonPath("$.accessToken").exists())
                    .andExpect(jsonPath("$.refreshToken").exists());
        }
    }

    @Nested
    @DisplayName("GET /auth/verify-email")
    class VerifyEmailTests {
        @Test
        @DisplayName("Deveria verificar email com token válido")
        void shouldVerifyEmail_WithValidToken() throws Exception {
            User user = createUnverifiedUser("test", "test@example.com", "pass");
            VerificationToken token = new VerificationToken(user, TokenType.EMAIL_VERIFICATION, 24);
            token = tokenRepository.save(token);

            mockMvc.perform(get("/auth/verify-email").param("token", token.getToken()))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.message").value("Email verificado com sucesso!"));

            User verified = userRepository.findById(user.getId()).orElseThrow();
            assertThat(verified.isEmailVerified()).isTrue();
        }

        @Test
        @DisplayName("Deveria retornar 404 quando token não existe")
        void shouldReturn404_WhenTokenNotFound() throws Exception {
            mockMvc.perform(get("/auth/verify-email").param("token",
                    "00000000-0000-0000-0000-000000000000")).andExpect(status().isNotFound());
        }
    }

    @Nested
    @DisplayName("POST /auth/forgot-password")
    class ForgotPasswordTests {
        @Test
        @DisplayName("Deveria retornar 202 quando email existe")
        void shouldReturn202_WhenEmailExists() throws Exception {
            createVerifiedUser("test", "test@example.com", "pass");

            String json = """
                    {"email":"test@example.com"}
                    """;

            mockMvc.perform(post("/auth/forgot-password").contentType(MediaType.APPLICATION_JSON)
                    .content(json)).andExpect(status().isAccepted());
        }

        @Test
        @DisplayName("Deveria retornar 202 mesmo quando email não existe")
        void shouldReturn202_EvenWhenEmailNotExists() throws Exception {
            String json = """
                    {"email":"nonexistent@example.com"}
                    """;

            mockMvc.perform(post("/auth/forgot-password").contentType(MediaType.APPLICATION_JSON)
                    .content(json)).andExpect(status().isAccepted());
        }
    }

    @Nested
    @DisplayName("PATCH /auth/reset-password")
    class ResetPasswordTests {
        @Test
        @DisplayName("Deveria resetar senha com token válido")
        void shouldResetPassword() throws Exception {
            User user = createVerifiedUser("test", "test@example.com", "oldpass");
            VerificationToken token = new VerificationToken(user, TokenType.PASSWORD_RESET, 1);
            token = tokenRepository.save(token);

            String json = String.format("""
                    {"token":"%s","newPassword":"NewP@ss123"}
                    """, token.getToken());

            mockMvc.perform(patch("/auth/reset-password").contentType(MediaType.APPLICATION_JSON)
                    .content(json)).andExpect(status().isNoContent());

            User updated = userRepository.findById(user.getId()).orElseThrow();
            assertThat(passwordEncoder.matches("NewP@ss123", updated.getPassword())).isTrue();
        }
    }

    @Nested
    @DisplayName("POST /auth/logout")
    class LogoutTests {
        @Test
        @DisplayName("Deveria fazer logout com token válido")
        void shouldLogout() throws Exception {
            User user = createVerifiedUser("test", "test@example.com", "pass");
            String accessToken = jwtUtil.generateToken(user);
            String refreshToken = jwtUtil.generateRefreshToken(user);

            String json = String.format("""
                    {"refreshToken":"%s"}
                    """, refreshToken);

            mockMvc.perform(post("/auth/logout").header("Authorization", "Bearer " + accessToken)
                    .contentType(MediaType.APPLICATION_JSON).content(json))
                    .andExpect(status().isNoContent());
        }
    }
}
