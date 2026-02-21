package com.atwo.paganois.security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import java.io.IOException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.test.util.ReflectionTestUtils;
import com.atwo.paganois.auth.services.TokenRevocationService;
import com.atwo.paganois.user.entities.Role;
import com.atwo.paganois.user.entities.User;
import jakarta.servlet.ServletException;

@ExtendWith(MockitoExtension.class)
@DisplayName("JwtAuthFilter - Unit Tests")
class JwtAuthFilterTest {

    @Mock
    private JwtUtil jwtUtil;

    @Mock
    private CustomUserDetailsService userDetailsService;

    @Mock
    private TokenRevocationService tokenRevocationService;

    @InjectMocks
    private JwtAuthFilter jwtAuthFilter;

    private MockHttpServletRequest request;
    private MockHttpServletResponse response;
    private MockFilterChain filterChain;

    private User validUser;
    private Role userRole;

    private static final String VALID_TOKEN = "valid.jwt.token";
    private static final String USERNAME = "testuser";

    @BeforeEach
    void setUp() {
        // Limpa o SecurityContext antes de cada teste
        SecurityContextHolder.clearContext();

        request = new MockHttpServletRequest();
        response = new MockHttpServletResponse();
        filterChain = new MockFilterChain();

        // Injeta mocks via reflection
        ReflectionTestUtils.setField(jwtAuthFilter, "jwtUtil", jwtUtil);
        ReflectionTestUtils.setField(jwtAuthFilter, "userDetailsService", userDetailsService);
        ReflectionTestUtils.setField(jwtAuthFilter, "tokenRevocationService",
                tokenRevocationService);

        userRole = new Role();
        userRole.setId(1L);
        userRole.setAuthority("ROLE_USER");

        validUser = new User();
        validUser.setId(1L);
        validUser.setUsername(USERNAME);
        validUser.setPassword("encodedPassword");
        validUser.setEmail("test@example.com");
        validUser.setRole(userRole);
        validUser.setEnabled(true);
        validUser.setEmailVerified(true);
    }

    // ========================================================================
    // TESTS: Valid token scenarios
    // ========================================================================

    @Nested
    @DisplayName("Cenários com token válido")
    class ValidTokenTests {

        @Test
        @DisplayName("Deveria extrair token do header Authorization")
        void shouldExtractToken_FromAuthorizationHeader() throws ServletException, IOException {
            // Arrange
            request.addHeader("Authorization", "Bearer " + VALID_TOKEN);
            when(jwtUtil.validateToken(VALID_TOKEN)).thenReturn(true);
            when(tokenRevocationService.isRevoked(VALID_TOKEN)).thenReturn(false);
            when(jwtUtil.validateTokenWithVersion(VALID_TOKEN)).thenReturn(true);
            when(jwtUtil.extractUsername(VALID_TOKEN)).thenReturn(USERNAME);
            when(userDetailsService.loadUserByUsername(USERNAME)).thenReturn(validUser);

            // Act
            jwtAuthFilter.doFilterInternal(request, response, filterChain);

            // Assert
            verify(jwtUtil).validateToken(VALID_TOKEN);
        }

        @Test
        @DisplayName("Deveria validar token antes de autenticar")
        void shouldValidateToken_BeforeAuthenticating() throws ServletException, IOException {
            // Arrange
            request.addHeader("Authorization", "Bearer " + VALID_TOKEN);
            when(jwtUtil.validateToken(VALID_TOKEN)).thenReturn(true);
            when(tokenRevocationService.isRevoked(VALID_TOKEN)).thenReturn(false);
            when(jwtUtil.validateTokenWithVersion(VALID_TOKEN)).thenReturn(true);
            when(jwtUtil.extractUsername(VALID_TOKEN)).thenReturn(USERNAME);
            when(userDetailsService.loadUserByUsername(USERNAME)).thenReturn(validUser);

            // Act
            jwtAuthFilter.doFilterInternal(request, response, filterChain);

            // Assert
            verify(jwtUtil).validateToken(VALID_TOKEN);
            verify(jwtUtil).validateTokenWithVersion(VALID_TOKEN);
        }

        @Test
        @DisplayName("Deveria verificar se token está revogado")
        void shouldCheckIfTokenIsRevoked() throws ServletException, IOException {
            // Arrange
            request.addHeader("Authorization", "Bearer " + VALID_TOKEN);
            when(jwtUtil.validateToken(VALID_TOKEN)).thenReturn(true);
            when(tokenRevocationService.isRevoked(VALID_TOKEN)).thenReturn(false);
            when(jwtUtil.validateTokenWithVersion(VALID_TOKEN)).thenReturn(true);
            when(jwtUtil.extractUsername(VALID_TOKEN)).thenReturn(USERNAME);
            when(userDetailsService.loadUserByUsername(USERNAME)).thenReturn(validUser);

            // Act
            jwtAuthFilter.doFilterInternal(request, response, filterChain);

            // Assert
            verify(tokenRevocationService).isRevoked(VALID_TOKEN);
        }

        @Test
        @DisplayName("Deveria carregar UserDetails pelo username extraído do token")
        void shouldLoadUserDetails_ByExtractedUsername() throws ServletException, IOException {
            // Arrange
            request.addHeader("Authorization", "Bearer " + VALID_TOKEN);
            when(jwtUtil.validateToken(VALID_TOKEN)).thenReturn(true);
            when(tokenRevocationService.isRevoked(VALID_TOKEN)).thenReturn(false);
            when(jwtUtil.validateTokenWithVersion(VALID_TOKEN)).thenReturn(true);
            when(jwtUtil.extractUsername(VALID_TOKEN)).thenReturn(USERNAME);
            when(userDetailsService.loadUserByUsername(USERNAME)).thenReturn(validUser);

            // Act
            jwtAuthFilter.doFilterInternal(request, response, filterChain);

            // Assert
            verify(jwtUtil).extractUsername(VALID_TOKEN);
            verify(userDetailsService).loadUserByUsername(USERNAME);
        }

        @Test
        @DisplayName("Deveria definir authorities do usuário no SecurityContext")
        void shouldSetUserAuthorities_InSecurityContext() throws ServletException, IOException {
            // Arrange
            request.addHeader("Authorization", "Bearer " + VALID_TOKEN);
            when(jwtUtil.validateToken(VALID_TOKEN)).thenReturn(true);
            when(tokenRevocationService.isRevoked(VALID_TOKEN)).thenReturn(false);
            when(jwtUtil.validateTokenWithVersion(VALID_TOKEN)).thenReturn(true);
            when(jwtUtil.extractUsername(VALID_TOKEN)).thenReturn(USERNAME);
            when(userDetailsService.loadUserByUsername(USERNAME)).thenReturn(validUser);

            // Act
            jwtAuthFilter.doFilterInternal(request, response, filterChain);

            // Assert
            assertThat(SecurityContextHolder.getContext().getAuthentication().getAuthorities())
                    .isNotEmpty().hasSize(1);
        }
    }
}
