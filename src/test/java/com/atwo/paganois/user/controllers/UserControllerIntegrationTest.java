package com.atwo.paganois.user.controllers;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.patch;
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

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
@DisplayName("UserController - Integration Tests")
class UserControllerIntegrationTest {

    @Autowired
    private MockMvc mockMvc;
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
    private User testUser;
    private String accessToken;

    @BeforeEach
    void setUp() {
        userRole = roleRepository.findByAuthority("ROLE_USER");
        if (userRole == null) {
            userRole = new Role();
            userRole.setAuthority("ROLE_USER");
            userRole = roleRepository.save(userRole);
        }

        testUser = createVerifiedUser("testuser", "test@example.com", "Password123!");
        accessToken = jwtUtil.generateToken(testUser);
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

    @Nested
    @DisplayName("GET /api/users/me")
    class GetMeTests {
        @Test
        @DisplayName("Deveria retornar perfil do usuário autenticado")
        void shouldReturnUserProfile() throws Exception {
            mockMvc.perform(get("/api/users/me").header("Authorization", "Bearer " + accessToken))
                    .andExpect(status().isOk()).andExpect(jsonPath("$.username").value("testuser"))
                    .andExpect(jsonPath("$.email").value("test@example.com"))
                    .andExpect(jsonPath("$.emailVerified").value(true));
        }

        @Test
        @DisplayName("Deveria retornar 401 sem autenticação")
        void shouldReturn401_WithoutAuth() throws Exception {
            mockMvc.perform(get("/api/users/me")).andExpect(status().isForbidden());
        }
    }

    @Nested
    @DisplayName("PATCH /api/users/me/password")
    class UpdatePasswordTests {
        @Test
        @DisplayName("Deveria alterar senha com sucesso")
        void shouldUpdatePassword() throws Exception {
            String json = """
                    {"oldPassword":"Password123!","newPassword":"NewP@ssw0rd!"}
                    """;

            mockMvc.perform(
                    patch("/api/users/me/password").header("Authorization", "Bearer " + accessToken)
                            .contentType(MediaType.APPLICATION_JSON).content(json))
                    .andExpect(status().isNoContent());

            User updated = userRepository.findById(testUser.getId()).orElseThrow();
            assertThat(passwordEncoder.matches("NewP@ssw0rd!", updated.getPassword())).isTrue();
        }

        @Test
        @DisplayName("Deveria retornar 401 quando senha antiga incorreta")
        void shouldReturn401_WithWrongOldPassword() throws Exception {
            String json = """
                    {"oldPassword":"WrongPass!","newPassword":"NewP@ssw0rd!"}
                    """;

            mockMvc.perform(
                    patch("/api/users/me/password").header("Authorization", "Bearer " + accessToken)
                            .contentType(MediaType.APPLICATION_JSON).content(json))
                    .andExpect(status().isUnauthorized());
        }

        @Test
        @DisplayName("Deveria retornar 400 quando nova senha é fraca")
        void shouldReturn400_WithWeakPassword() throws Exception {
            String json = """
                    {"oldPassword":"Password123!","newPassword":"weak"}
                    """;

            mockMvc.perform(
                    patch("/api/users/me/password").header("Authorization", "Bearer " + accessToken)
                            .contentType(MediaType.APPLICATION_JSON).content(json))
                    .andExpect(status().isBadRequest());
        }
    }

    @Nested
    @DisplayName("PATCH /api/users/me/email")
    class RequestEmailChangeTests {
        @Test
        @DisplayName("Deveria solicitar mudança de email")
        void shouldRequestEmailChange() throws Exception {
            String json = """
                    {"newEmail":"newemail@example.com"}
                    """;

            mockMvc.perform(
                    patch("/api/users/me/email").header("Authorization", "Bearer " + accessToken)
                            .contentType(MediaType.APPLICATION_JSON).content(json))
                    .andExpect(status().isOk());
        }

        @Test
        @DisplayName("Deveria retornar 409 quando email já existe")
        void shouldReturn409_WhenEmailExists() throws Exception {
            createVerifiedUser("other", "existing@example.com", "pass");

            String json = """
                    {"newEmail":"existing@example.com"}
                    """;

            mockMvc.perform(
                    patch("/api/users/me/email").header("Authorization", "Bearer " + accessToken)
                            .contentType(MediaType.APPLICATION_JSON).content(json))
                    .andExpect(status().isConflict());
        }
    }

    @Nested
    @DisplayName("GET /api/users/me/email/confirm")
    class ConfirmEmailChangeTests {
        @Test
        @DisplayName("Deveria confirmar mudança de email")
        void shouldConfirmEmailChange() throws Exception {
            VerificationToken token =
                    new VerificationToken(testUser, TokenType.EMAIL_CHANGE, 1, "new@example.com");
            token = tokenRepository.save(token);

            mockMvc.perform(get("/api/users/me/email/confirm")
                    .header("Authorization", "Bearer " + accessToken)
                    .param("token", token.getToken())).andExpect(status().isOk());

            User updated = userRepository.findById(testUser.getId()).orElseThrow();
            assertThat(updated.getEmail()).isEqualTo("new@example.com");
        }

        @Test
        @DisplayName("Deveria retornar 404 quando token não existe")
        void shouldReturn404_WhenTokenNotFound() throws Exception {
            mockMvc.perform(get("/api/users/me/email/confirm")
                    .header("Authorization", "Bearer " + accessToken)
                    .param("token", "00000000-0000-0000-0000-000000000000"))
                    .andExpect(status().isNotFound());
        }

        @Test
        @DisplayName("Deveria retornar 403 quando token de outro usuário")
        void shouldReturn403_WhenTokenBelongsToOtherUser() throws Exception {
            User otherUser = createVerifiedUser("other", "other@example.com", "pass");
            VerificationToken token =
                    new VerificationToken(otherUser, TokenType.EMAIL_CHANGE, 1, "new@example.com");
            token = tokenRepository.save(token);

            mockMvc.perform(get("/api/users/me/email/confirm")
                    .header("Authorization", "Bearer " + accessToken)
                    .param("token", token.getToken())).andExpect(status().isForbidden());
        }
    }
}
