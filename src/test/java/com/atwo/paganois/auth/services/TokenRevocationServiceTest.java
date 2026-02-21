package com.atwo.paganois.auth.services;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import java.time.Duration;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.util.ReflectionTestUtils;
import com.atwo.paganois.auth.repositories.RevokedTokenRepository;

/**
 * Unit tests for TokenRevocationService
 * 
 * Structure: - revokeToken() - Revoke single refresh token - revokeTokenPair() - Revoke access and
 * refresh tokens - isRevoked() - Check if token is revoked - revokeAllUserTokens() - Revoke all
 * user tokens (global logout) - getCurrentUserTokenVersion() - Get current user token version
 */
@ExtendWith(MockitoExtension.class)
@DisplayName("TokenRevocationService - Unit Tests")
class TokenRevocationServiceTest {

    @Mock
    private RevokedTokenRepository revokedTokenRepository;

    private TokenRevocationService tokenRevocationService;

    private static final String REFRESH_TOKEN = "refresh.jwt.token";
    private static final String ACCESS_TOKEN = "access.jwt.token";
    private static final String USERNAME = "testuser";
    private static final Long REFRESH_EXPIRATION = 604800000L; // 7 days in ms
    private static final Long ACCESS_EXPIRATION = 900000L; // 15 min in ms

    @BeforeEach
    void setUp() {
        tokenRevocationService = new TokenRevocationService();
        ReflectionTestUtils.setField(tokenRevocationService, "revokedTokenRepository",
                revokedTokenRepository);
        ReflectionTestUtils.setField(tokenRevocationService, "refreshExpiration",
                REFRESH_EXPIRATION);
        ReflectionTestUtils.setField(tokenRevocationService, "accessExpiration", ACCESS_EXPIRATION);
    }

    // ========================================================================
    // TESTS: revokeToken()
    // ========================================================================

    @Nested
    @DisplayName("revokeToken() - Revogar token individual (refresh rotation)")
    class RevokeTokenTests {

        @Test
        @DisplayName("Deveria salvar token no repositório com TTL de refresh")
        void shouldSaveToken_WithRefreshTTL() {
            // Arrange
            ArgumentCaptor<Duration> ttlCaptor = ArgumentCaptor.forClass(Duration.class);

            // Act
            tokenRevocationService.revokeToken(REFRESH_TOKEN);

            // Assert
            verify(revokedTokenRepository).save(eq(REFRESH_TOKEN), ttlCaptor.capture());

            Duration capturedTtl = ttlCaptor.getValue();
            assertThat(capturedTtl.toMillis()).isEqualTo(REFRESH_EXPIRATION);
        }

        @Test
        @DisplayName("Deveria usar expiração de refresh token como TTL")
        void shouldUseRefreshExpiration_AsTTL() {
            // Arrange
            ArgumentCaptor<Duration> ttlCaptor = ArgumentCaptor.forClass(Duration.class);

            // Act
            tokenRevocationService.revokeToken(REFRESH_TOKEN);

            // Assert
            verify(revokedTokenRepository).save(eq(REFRESH_TOKEN), ttlCaptor.capture());
            assertThat(ttlCaptor.getValue()).isEqualTo(Duration.ofMillis(REFRESH_EXPIRATION));
        }
    }

    // ========================================================================
    // TESTS: revokeTokenPair()
    // ========================================================================

    @Nested
    @DisplayName("revokeTokenPair() - Revogar par de tokens (logout)")
    class RevokeTokenPairTests {

        @Test
        @DisplayName("Deveria revogar access token com TTL correto")
        void shouldRevokeAccessToken_WithCorrectTTL() {
            // Act
            tokenRevocationService.revokeTokenPair(ACCESS_TOKEN, REFRESH_TOKEN);

            // Assert - Verifica sem assumir ordem de execução
            verify(revokedTokenRepository).save(eq(ACCESS_TOKEN),
                    eq(Duration.ofMillis(ACCESS_EXPIRATION)));
        }

        @Test
        @DisplayName("Deveria revogar refresh token com TTL correto")
        void shouldRevokeRefreshToken_WithCorrectTTL() {
            // Act
            tokenRevocationService.revokeTokenPair(ACCESS_TOKEN, REFRESH_TOKEN);

            // Assert - Verifica sem assumir ordem de execução
            verify(revokedTokenRepository).save(eq(REFRESH_TOKEN),
                    eq(Duration.ofMillis(REFRESH_EXPIRATION)));
        }

        @Test
        @DisplayName("Deveria usar TTLs diferentes para access e refresh tokens")
        void shouldUseDifferentTTLs_ForAccessAndRefreshTokens() {
            // Act
            tokenRevocationService.revokeTokenPair(ACCESS_TOKEN, REFRESH_TOKEN);

            // Assert - Verifica que os TTLs são diferentes
            verify(revokedTokenRepository).save(eq(ACCESS_TOKEN),
                    eq(Duration.ofMillis(ACCESS_EXPIRATION)));
            verify(revokedTokenRepository).save(eq(REFRESH_TOKEN),
                    eq(Duration.ofMillis(REFRESH_EXPIRATION)));

            assertThat(ACCESS_EXPIRATION).isNotEqualTo(REFRESH_EXPIRATION);
        }
    }

    // ========================================================================
    // TESTS: isRevoked()
    // ========================================================================

    @Nested
    @DisplayName("isRevoked() - Verificar se token está revogado")
    class IsRevokedTests {

        @Test
        @DisplayName("Deveria retornar true quando token está revogado")
        void shouldReturnTrue_WhenTokenIsRevoked() {
            // Arrange
            when(revokedTokenRepository.exists(REFRESH_TOKEN)).thenReturn(true);

            // Act
            boolean result = tokenRevocationService.isRevoked(REFRESH_TOKEN);

            // Assert
            assertThat(result).isTrue();
            verify(revokedTokenRepository).exists(REFRESH_TOKEN);
        }

        @Test
        @DisplayName("Deveria retornar false quando token não está revogado")
        void shouldReturnFalse_WhenTokenIsNotRevoked() {
            // Arrange
            when(revokedTokenRepository.exists(REFRESH_TOKEN)).thenReturn(false);

            // Act
            boolean result = tokenRevocationService.isRevoked(REFRESH_TOKEN);

            // Assert
            assertThat(result).isFalse();
            verify(revokedTokenRepository).exists(REFRESH_TOKEN);
        }

        @Test
        @DisplayName("Deveria delegar verificação para o repositório")
        void shouldDelegateCheck_ToRepository() {
            // Arrange
            when(revokedTokenRepository.exists(REFRESH_TOKEN)).thenReturn(false);

            // Act
            tokenRevocationService.isRevoked(REFRESH_TOKEN);

            // Assert
            verify(revokedTokenRepository).exists(REFRESH_TOKEN);
        }
    }

    // ========================================================================
    // TESTS: revokeAllUserTokens()
    // ========================================================================

    @Nested
    @DisplayName("revokeAllUserTokens() - Revogar todos os tokens do usuário (logout global)")
    class RevokeAllUserTokensTests {

        @Test
        @DisplayName("Deveria incrementar versão de token do usuário")
        void shouldIncrementUserTokenVersion() {
            // Act
            tokenRevocationService.revokeAllUserTokens(USERNAME);

            // Assert
            verify(revokedTokenRepository).incrementUserTokenVersion(USERNAME);
        }

        @Test
        @DisplayName("Deveria passar username correto para o repositório")
        void shouldPassCorrectUsername_ToRepository() {
            // Arrange
            ArgumentCaptor<String> usernameCaptor = ArgumentCaptor.forClass(String.class);

            // Act
            tokenRevocationService.revokeAllUserTokens(USERNAME);

            // Assert
            verify(revokedTokenRepository).incrementUserTokenVersion(usernameCaptor.capture());
            assertThat(usernameCaptor.getValue()).isEqualTo(USERNAME);
        }

        @Test
        @DisplayName("Deveria funcionar com diferentes usernames")
        void shouldWork_WithDifferentUsernames() {
            // Arrange
            String user1 = "user1";
            String user2 = "user2";

            // Act
            tokenRevocationService.revokeAllUserTokens(user1);
            tokenRevocationService.revokeAllUserTokens(user2);

            // Assert
            verify(revokedTokenRepository).incrementUserTokenVersion(user1);
            verify(revokedTokenRepository).incrementUserTokenVersion(user2);
        }
    }

    // ========================================================================
    // TESTS: getCurrentUserTokenVersion()
    // ========================================================================

    @Nested
    @DisplayName("getCurrentUserTokenVersion() - Obter versão atual de tokens do usuário")
    class GetCurrentUserTokenVersionTests {

        @Test
        @DisplayName("Deveria retornar versão atual do repositório")
        void shouldReturnCurrentVersion_FromRepository() {
            // Arrange
            Long expectedVersion = 5L;
            when(revokedTokenRepository.getUserTokenVersion(USERNAME)).thenReturn(expectedVersion);

            // Act
            Long result = tokenRevocationService.getCurrentUserTokenVersion(USERNAME);

            // Assert
            assertThat(result).isEqualTo(expectedVersion);
            verify(revokedTokenRepository).getUserTokenVersion(USERNAME);
        }

        @Test
        @DisplayName("Deveria retornar versão inicial quando usuário não tem versão")
        void shouldReturnInitialVersion_WhenUserHasNoVersion() {
            // Arrange
            Long initialVersion = 0L;
            when(revokedTokenRepository.getUserTokenVersion(USERNAME)).thenReturn(initialVersion);

            // Act
            Long result = tokenRevocationService.getCurrentUserTokenVersion(USERNAME);

            // Assert
            assertThat(result).isEqualTo(initialVersion);
        }

        @Test
        @DisplayName("Deveria retornar versões diferentes para usuários diferentes")
        void shouldReturnDifferentVersions_ForDifferentUsers() {
            // Arrange
            String user1 = "user1";
            String user2 = "user2";
            when(revokedTokenRepository.getUserTokenVersion(user1)).thenReturn(3L);
            when(revokedTokenRepository.getUserTokenVersion(user2)).thenReturn(7L);

            // Act
            Long version1 = tokenRevocationService.getCurrentUserTokenVersion(user1);
            Long version2 = tokenRevocationService.getCurrentUserTokenVersion(user2);

            // Assert
            assertThat(version1).isEqualTo(3L);
            assertThat(version2).isEqualTo(7L);
            assertThat(version1).isNotEqualTo(version2);
        }

        @Test
        @DisplayName("Deveria delegar para o repositório")
        void shouldDelegate_ToRepository() {
            // Arrange
            when(revokedTokenRepository.getUserTokenVersion(USERNAME)).thenReturn(1L);

            // Act
            tokenRevocationService.getCurrentUserTokenVersion(USERNAME);

            // Assert
            verify(revokedTokenRepository).getUserTokenVersion(USERNAME);
        }
    }

    // ========================================================================
    // TESTS: Integration scenarios
    // ========================================================================

    @Nested
    @DisplayName("Cenários de integração")
    class IntegrationScenariosTests {

        @Test
        @DisplayName("Deveria permitir revogar token e depois verificar se está revogado")
        void shouldAllowRevoke_ThenCheckIfRevoked() {
            // Arrange
            when(revokedTokenRepository.exists(REFRESH_TOKEN)).thenReturn(true);

            // Act
            tokenRevocationService.revokeToken(REFRESH_TOKEN);
            boolean isRevoked = tokenRevocationService.isRevoked(REFRESH_TOKEN);

            // Assert
            assertThat(isRevoked).isTrue();
            verify(revokedTokenRepository).save(eq(REFRESH_TOKEN), any(Duration.class));
            verify(revokedTokenRepository).exists(REFRESH_TOKEN);
        }

        @Test
        @DisplayName("Deveria permitir logout global e depois obter nova versão")
        void shouldAllowGlobalLogout_ThenGetNewVersion() {
            // Arrange
            when(revokedTokenRepository.getUserTokenVersion(USERNAME)).thenReturn(1L) // Versão
                                                                                      // antes
                    .thenReturn(2L); // Versão depois

            // Act
            Long versionBefore = tokenRevocationService.getCurrentUserTokenVersion(USERNAME);
            tokenRevocationService.revokeAllUserTokens(USERNAME);
            Long versionAfter = tokenRevocationService.getCurrentUserTokenVersion(USERNAME);

            // Assert
            assertThat(versionBefore).isEqualTo(1L);
            assertThat(versionAfter).isEqualTo(2L);
            verify(revokedTokenRepository).incrementUserTokenVersion(USERNAME);
        }

        @Test
        @DisplayName("Deveria permitir revogar par de tokens e verificar ambos")
        void shouldAllowRevokePair_ThenCheckBoth() {
            // Arrange
            when(revokedTokenRepository.exists(ACCESS_TOKEN)).thenReturn(true);
            when(revokedTokenRepository.exists(REFRESH_TOKEN)).thenReturn(true);

            // Act
            tokenRevocationService.revokeTokenPair(ACCESS_TOKEN, REFRESH_TOKEN);
            boolean accessRevoked = tokenRevocationService.isRevoked(ACCESS_TOKEN);
            boolean refreshRevoked = tokenRevocationService.isRevoked(REFRESH_TOKEN);

            // Assert
            assertThat(accessRevoked).isTrue();
            assertThat(refreshRevoked).isTrue();
            verify(revokedTokenRepository).save(eq(ACCESS_TOKEN), any(Duration.class));
            verify(revokedTokenRepository).save(eq(REFRESH_TOKEN), any(Duration.class));
        }
    }
}
