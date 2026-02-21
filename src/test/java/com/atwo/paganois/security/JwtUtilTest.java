package com.atwo.paganois.security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;
import java.util.Date;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.springframework.test.util.ReflectionTestUtils;
import com.atwo.paganois.auth.services.TokenRevocationService;
import com.atwo.paganois.user.entities.Role;
import com.atwo.paganois.user.entities.User;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;

/**
 * Unit tests for JwtUtil
 * 
 * CRITICAL SECURITY COMPONENT - Extensive testing required
 * 
 * Structure: - generateToken() - Access token generation - generateRefreshToken() - Refresh token
 * generation - validateToken() - Token validation - validateTokenWithVersion() - Version-aware
 * validation - extractUsername() - Extract username claim - extractExpiration() - Extract
 * expiration claim - extractVersion() - Extract version claim - Security scenarios - Tampering,
 * expiration, malformed tokens
 */
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
@DisplayName("JwtUtil - Unit Tests")
class JwtUtilTest {

    @Mock
    private TokenRevocationService tokenRevocationService;

    private JwtUtil jwtUtil;

    private User validUser;
    private Role userRole;

    private static final String SECRET =
            "dGVzdC1zZWNyZXQta2V5LWZvci1qd3QtdG9rZW4tZ2VuZXJhdGlvbi1hbmQtdmFsaWRhdGlvbi0xMjM0NTY=";
    private static final Long EXPIRATION = 900000L; // 15 minutos
    private static final Long REFRESH_EXPIRATION = 604800000L; // 7 dias
    private static final String USERNAME = "testuser";
    private static final Long CURRENT_VERSION = 1L;

    @BeforeEach
    void setUp() {
        jwtUtil = new JwtUtil(tokenRevocationService);

        // Injeta valores @Value via reflection
        ReflectionTestUtils.setField(jwtUtil, "secret", SECRET);
        ReflectionTestUtils.setField(jwtUtil, "expiration", EXPIRATION);
        ReflectionTestUtils.setField(jwtUtil, "refreshExpiration", REFRESH_EXPIRATION);

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

        when(tokenRevocationService.getCurrentUserTokenVersion(USERNAME))
                .thenReturn(CURRENT_VERSION);
    }

    // ========================================================================
    // TESTS: generateToken() - Access token
    // ========================================================================

    @Nested
    @DisplayName("generateToken() - Gerar access token")
    class GenerateTokenTests {

        @Test
        @DisplayName("Deveria gerar token válido")
        void shouldGenerateValidToken() {
            // Act
            String token = jwtUtil.generateToken(validUser);

            // Assert
            assertThat(token).isNotNull().isNotEmpty();
            assertThat(jwtUtil.validateToken(token)).isTrue();
        }

        @Test
        @DisplayName("Deveria incluir username no subject")
        void shouldIncludeUsername_InSubject() {
            // Act
            String token = jwtUtil.generateToken(validUser);

            // Assert
            String extractedUsername = jwtUtil.extractUsername(token);
            assertThat(extractedUsername).isEqualTo(USERNAME);
        }

        @Test
        @DisplayName("Deveria incluir versão nos claims")
        void shouldIncludeVersion_InClaims() {
            // Act
            String token = jwtUtil.generateToken(validUser);

            // Assert
            Long version = jwtUtil.extractVersion(token);
            assertThat(version).isEqualTo(CURRENT_VERSION);
        }

        @Test
        @DisplayName("Deveria incluir authorities nos claims")
        void shouldIncludeAuthorities_InClaims() {
            // Act
            String token = jwtUtil.generateToken(validUser);

            // Assert
            @SuppressWarnings("unchecked")
            java.util.List<String> authorities = jwtUtil.extractClaim(token,
                    claims -> (java.util.List<String>) claims.get("authorities"));

            assertThat(authorities).isNotNull().contains("ROLE_USER");
        }

        @Test
        @DisplayName("Deveria definir expiração para 15 minutos")
        void shouldSetExpiration_To15Minutes() {
            // Act
            String token = jwtUtil.generateToken(validUser);

            // Assert
            Date expiration = jwtUtil.extractExpiration(token);
            Date now = new Date();
            Date expected = new Date(now.getTime() + EXPIRATION);

            assertThat(expiration).isCloseTo(expected, 1000L);
        }

        @Test
        @DisplayName("Deveria gerar tokens diferentes para cada chamada")
        void shouldGenerateDifferentTokens_ForEachCall() throws InterruptedException {
            // Act
            String token1 = jwtUtil.generateToken(validUser);

            // Espera 1 segundo para garantir timestamp diferente (iat tem precisão de segundos)
            Thread.sleep(1000);

            String token2 = jwtUtil.generateToken(validUser);

            // Assert
            assertThat(token1).isNotEqualTo(token2);
        }
    }

    // ========================================================================
    // TESTS: generateRefreshToken() - Refresh token
    // ========================================================================

    @Nested
    @DisplayName("generateRefreshToken() - Gerar refresh token")
    class GenerateRefreshTokenTests {

        @Test
        @DisplayName("Deveria gerar token válido")
        void shouldGenerateValidToken() {
            // Act
            String token = jwtUtil.generateRefreshToken(validUser);

            // Assert
            assertThat(token).isNotNull().isNotEmpty();
            assertThat(jwtUtil.validateToken(token)).isTrue();
        }

        @Test
        @DisplayName("Deveria definir expiração para 7 dias")
        void shouldSetExpiration_To7Days() {
            // Act
            String token = jwtUtil.generateRefreshToken(validUser);

            // Assert
            Date expiration = jwtUtil.extractExpiration(token);
            Date now = new Date();
            Date expected = new Date(now.getTime() + REFRESH_EXPIRATION);

            assertThat(expiration).isCloseTo(expected, 1000L);
        }

        @Test
        @DisplayName("Deveria ter expiração maior que access token")
        void shouldHaveLongerExpiration_ThanAccessToken() {
            // Act
            String accessToken = jwtUtil.generateToken(validUser);
            String refreshToken = jwtUtil.generateRefreshToken(validUser);

            // Assert
            Date accessExpiration = jwtUtil.extractExpiration(accessToken);
            Date refreshExpiration = jwtUtil.extractExpiration(refreshToken);

            assertThat(refreshExpiration).isAfter(accessExpiration);
        }
    }

    // ========================================================================
    // TESTS: validateToken() - Token validation
    // ========================================================================

    @Nested
    @DisplayName("validateToken() - Validar token")
    class ValidateTokenTests {

        @Test
        @DisplayName("Deveria validar token correto")
        void shouldValidate_CorrectToken() {
            // Arrange
            String token = jwtUtil.generateToken(validUser);

            // Act
            boolean isValid = jwtUtil.validateToken(token);

            // Assert
            assertThat(isValid).isTrue();
        }

        @Test
        @DisplayName("Deveria rejeitar token malformado")
        void shouldReject_MalformedToken() {
            // Arrange
            String malformedToken = "malformed.token.here";

            // Act
            boolean isValid = jwtUtil.validateToken(malformedToken);

            // Assert
            assertThat(isValid).isFalse();
        }

        @Test
        @DisplayName("Deveria rejeitar token vazio")
        void shouldReject_EmptyToken() {
            // Act
            boolean isValid = jwtUtil.validateToken("");

            // Assert
            assertThat(isValid).isFalse();
        }

        @Test
        @DisplayName("Deveria rejeitar token null")
        void shouldReject_NullToken() {
            // Act
            boolean isValid = jwtUtil.validateToken(null);

            // Assert
            assertThat(isValid).isFalse();
        }

        @Test
        @DisplayName("Deveria rejeitar token com assinatura inválida")
        void shouldReject_TokenWithInvalidSignature() {
            // Arrange - Cria token com secret diferente
            String differentSecret =
                    "ZGlmZmVyZW50LXNlY3JldC1rZXktZm9yLWp3dC10b2tlbi10ZXN0aW5nLTEyMzQ1Ng==";
            String token = Jwts.builder().subject(USERNAME).issuedAt(new Date())
                    .expiration(new Date(System.currentTimeMillis() + EXPIRATION))
                    .signWith(Keys.hmacShaKeyFor(Decoders.BASE64.decode(differentSecret)))
                    .compact();

            // Act
            boolean isValid = jwtUtil.validateToken(token);

            // Assert
            assertThat(isValid).isFalse();
        }

        @Test
        @DisplayName("Deveria rejeitar token expirado")
        void shouldReject_ExpiredToken() {
            // Arrange - Cria token já expirado
            String expiredToken = Jwts.builder().subject(USERNAME)
                    .issuedAt(new Date(System.currentTimeMillis() - 2000))
                    .expiration(new Date(System.currentTimeMillis() - 1000))
                    .signWith(Keys.hmacShaKeyFor(Decoders.BASE64.decode(SECRET))).compact();

            // Act
            boolean isValid = jwtUtil.validateToken(expiredToken);

            // Assert
            assertThat(isValid).isFalse();
        }
    }

    // ========================================================================
    // TESTS: validateTokenWithVersion() - Version validation
    // ========================================================================

    @Nested
    @DisplayName("validateTokenWithVersion() - Validar token com versão")
    class ValidateTokenWithVersionTests {

        @Test
        @DisplayName("Deveria aceitar token com versão atual")
        void shouldAccept_TokenWithCurrentVersion() {
            // Arrange
            String token = jwtUtil.generateToken(validUser);

            // Act
            boolean isValid = jwtUtil.validateTokenWithVersion(token);

            // Assert
            assertThat(isValid).isTrue();
        }

        @Test
        @DisplayName("Deveria rejeitar token com versão antiga")
        void shouldReject_TokenWithOldVersion() {
            // Arrange
            String token = jwtUtil.generateToken(validUser);

            // Simula incremento de versão (logout global)
            when(tokenRevocationService.getCurrentUserTokenVersion(USERNAME)).thenReturn(2L);

            // Act
            boolean isValid = jwtUtil.validateTokenWithVersion(token);

            // Assert
            assertThat(isValid).isFalse();
        }

        @Test
        @DisplayName("Deveria aceitar token com versão maior (edge case)")
        void shouldAccept_TokenWithNewerVersion() {
            // Arrange
            when(tokenRevocationService.getCurrentUserTokenVersion(USERNAME)).thenReturn(5L);
            String token = jwtUtil.generateToken(validUser);

            // Volta para versão menor
            when(tokenRevocationService.getCurrentUserTokenVersion(USERNAME)).thenReturn(3L);

            // Act
            boolean isValid = jwtUtil.validateTokenWithVersion(token);

            // Assert - Token com versão 5 >= versão atual 3
            assertThat(isValid).isTrue();
        }

        @Test
        @DisplayName("Deveria rejeitar quando validateToken falha")
        void shouldReject_WhenValidateTokenFails() {
            // Arrange
            String invalidToken = "invalid.token";

            // Act
            boolean isValid = jwtUtil.validateTokenWithVersion(invalidToken);

            // Assert
            assertThat(isValid).isFalse();
        }
    }

    // ========================================================================
    // TESTS: extractUsername()
    // ========================================================================

    @Nested
    @DisplayName("extractUsername() - Extrair username")
    class ExtractUsernameTests {

        @Test
        @DisplayName("Deveria extrair username corretamente")
        void shouldExtractUsername_Correctly() {
            // Arrange
            String token = jwtUtil.generateToken(validUser);

            // Act
            String username = jwtUtil.extractUsername(token);

            // Assert
            assertThat(username).isEqualTo(USERNAME);
        }

        @Test
        @DisplayName("Deveria extrair username de diferentes usuários")
        void shouldExtractUsername_FromDifferentUsers() {
            // Arrange
            User user1 = new User();
            user1.setUsername("user1");
            user1.setRole(userRole);

            User user2 = new User();
            user2.setUsername("user2");
            user2.setRole(userRole);

            when(tokenRevocationService.getCurrentUserTokenVersion("user1")).thenReturn(1L);
            when(tokenRevocationService.getCurrentUserTokenVersion("user2")).thenReturn(1L);

            String token1 = jwtUtil.generateToken(user1);
            String token2 = jwtUtil.generateToken(user2);

            // Act
            String extractedUser1 = jwtUtil.extractUsername(token1);
            String extractedUser2 = jwtUtil.extractUsername(token2);

            // Assert
            assertThat(extractedUser1).isEqualTo("user1");
            assertThat(extractedUser2).isEqualTo("user2");
        }
    }

    // ========================================================================
    // TESTS: extractExpiration()
    // ========================================================================

    @Nested
    @DisplayName("extractExpiration() - Extrair expiração")
    class ExtractExpirationTests {

        @Test
        @DisplayName("Deveria extrair data de expiração corretamente")
        void shouldExtractExpiration_Correctly() {
            // Arrange
            String token = jwtUtil.generateToken(validUser);

            // Act
            Date expiration = jwtUtil.extractExpiration(token);

            // Assert
            assertThat(expiration).isNotNull().isAfter(new Date());
        }

        @Test
        @DisplayName("Deveria extrair expiração no futuro")
        void shouldExtractExpiration_InFuture() {
            // Arrange
            String token = jwtUtil.generateToken(validUser);

            // Act
            Date expiration = jwtUtil.extractExpiration(token);

            // Assert
            assertThat(expiration).isAfter(new Date());
        }
    }

    // ========================================================================
    // TESTS: extractVersion()
    // ========================================================================

    @Nested
    @DisplayName("extractVersion() - Extrair versão")
    class ExtractVersionTests {

        @Test
        @DisplayName("Deveria extrair versão corretamente")
        void shouldExtractVersion_Correctly() {
            // Arrange
            String token = jwtUtil.generateToken(validUser);

            // Act
            Long version = jwtUtil.extractVersion(token);

            // Assert
            assertThat(version).isEqualTo(CURRENT_VERSION);
        }

        @Test
        @DisplayName("Deveria retornar 0 para token sem versão")
        void shouldReturn0_ForTokenWithoutVersion() {
            // Arrange - Cria token sem claim de versão
            String tokenWithoutVersion = Jwts.builder().subject(USERNAME).issuedAt(new Date())
                    .expiration(new Date(System.currentTimeMillis() + EXPIRATION))
                    .signWith(Keys.hmacShaKeyFor(Decoders.BASE64.decode(SECRET))).compact();

            // Act
            Long version = jwtUtil.extractVersion(tokenWithoutVersion);

            // Assert
            assertThat(version).isEqualTo(0L);
        }

        @Test
        @DisplayName("Deveria extrair versões diferentes")
        void shouldExtractDifferentVersions() {
            // Arrange
            when(tokenRevocationService.getCurrentUserTokenVersion(USERNAME)).thenReturn(1L)
                    .thenReturn(2L);

            String token1 = jwtUtil.generateToken(validUser);
            String token2 = jwtUtil.generateToken(validUser);

            // Act
            Long version1 = jwtUtil.extractVersion(token1);
            Long version2 = jwtUtil.extractVersion(token2);

            // Assert
            assertThat(version1).isEqualTo(1L);
            assertThat(version2).isEqualTo(2L);
        }
    }

    // ========================================================================
    // TESTS: Security scenarios
    // ========================================================================

    @Nested
    @DisplayName("Cenários de segurança")
    class SecurityScenariosTests {

        @Test
        @DisplayName("Deveria rejeitar token adulterado (claims modificados)")
        void shouldReject_TamperedToken() {
            // Arrange
            String validToken = jwtUtil.generateToken(validUser);

            // Tenta adulterar o token (adiciona caractere no meio)
            String[] parts = validToken.split("\\.");
            String tamperedToken = parts[0] + "X." + parts[1] + "." + parts[2];

            // Act
            boolean isValid = jwtUtil.validateToken(tamperedToken);

            // Assert
            assertThat(isValid).isFalse();
        }

        @Test
        @DisplayName("Deveria validar apenas tokens assinados com secret correto")
        void shouldValidateOnly_TokensWithCorrectSecret() {
            // Arrange
            String correctToken = jwtUtil.generateToken(validUser);

            String wrongSecretToken = Jwts.builder().subject(USERNAME).issuedAt(new Date())
                    .expiration(new Date(System.currentTimeMillis() + EXPIRATION))
                    .signWith(Keys.hmacShaKeyFor(Decoders.BASE64.decode(
                            "d3Jvbmctc2VjcmV0LWtleS1mb3Itand0LXRva2VuLWdlbmVyYXRpb24tMTIzNDU2")))
                    .compact();

            // Act
            boolean correctValid = jwtUtil.validateToken(correctToken);
            boolean wrongValid = jwtUtil.validateToken(wrongSecretToken);

            // Assert
            assertThat(correctValid).isTrue();
            assertThat(wrongValid).isFalse();
        }

        @Test
        @DisplayName("Deveria token de refresh ter tempo maior que access")
        void shouldRefreshToken_HaveLongerExpiration() {
            // Act
            String accessToken = jwtUtil.generateToken(validUser);
            String refreshToken = jwtUtil.generateRefreshToken(validUser);

            Date accessExp = jwtUtil.extractExpiration(accessToken);
            Date refreshExp = jwtUtil.extractExpiration(refreshToken);

            // Assert
            long accessTime = accessExp.getTime() - new Date().getTime();
            long refreshTime = refreshExp.getTime() - new Date().getTime();

            assertThat(refreshTime).isGreaterThan(accessTime);
        }
    }
}
