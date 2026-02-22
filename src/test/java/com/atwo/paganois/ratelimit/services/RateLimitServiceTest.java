package com.atwo.paganois.ratelimit.services;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import com.atwo.paganois.ratelimit.config.RateLimitConfig;
import com.atwo.paganois.ratelimit.config.RateLimitConfig.EndpointLimit;
import com.atwo.paganois.ratelimit.services.RateLimitService.RateLimitResult;

/**
 * Unit tests for RateLimitService
 * 
 * Structure: - tryConsumeLogin() - Login rate limiting - tryConsumeRegister() - Register rate
 * limiting - tryConsumeForgotPassword() - Forgot password rate limiting -
 * tryConsumeResendVerification() - Resend verification rate limiting - tryConsumeGeneral() -
 * General endpoints rate limiting - Rate limit scenarios - Token consumption and refill behavior
 */
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
@DisplayName("RateLimitService - Unit Tests")
class RateLimitServiceTest {

    @Mock
    private RateLimitConfig config;

    private RateLimitService rateLimitService;

    private static final String IP_ADDRESS = "192.168.1.1";
    private static final String ANOTHER_IP = "192.168.1.2";

    @BeforeEach
    void setUp() {
        // Configura limites padrão
        when(config.getLogin()).thenReturn(new EndpointLimit(5, 5, 1));
        when(config.getRegister()).thenReturn(new EndpointLimit(3, 3, 60));
        when(config.getForgotPassword()).thenReturn(new EndpointLimit(3, 3, 60));
        when(config.getResendVerification()).thenReturn(new EndpointLimit(3, 3, 60));
        when(config.getGeneral()).thenReturn(new EndpointLimit(40, 40, 1));
        when(config.getCacheMaxSize()).thenReturn(10000);
        when(config.getCacheExpireMinutes()).thenReturn(60);

        rateLimitService = new RateLimitService(config);
    }

    // ========================================================================
    // TESTS: tryConsumeLogin()
    // ========================================================================

    @Nested
    @DisplayName("tryConsumeLogin() - Rate limiting de login")
    class TryConsumeLoginTests {

        @Test
        @DisplayName("Deveria permitir primeira requisição")
        void shouldAllow_FirstRequest() {
            // Act
            RateLimitResult result = rateLimitService.tryConsumeLogin(IP_ADDRESS);

            // Assert
            assertThat(result.allowed()).isTrue();
            assertThat(result.remainingTokens()).isEqualTo(4); // 5 - 1 = 4
            assertThat(result.retryAfterSeconds()).isEqualTo(0);
        }

        @Test
        @DisplayName("Deveria permitir até o limite de capacidade")
        void shouldAllow_UpToCapacity() {
            // Act - Consome 5 tokens (capacidade = 5)
            RateLimitResult result1 = rateLimitService.tryConsumeLogin(IP_ADDRESS);
            RateLimitResult result2 = rateLimitService.tryConsumeLogin(IP_ADDRESS);
            RateLimitResult result3 = rateLimitService.tryConsumeLogin(IP_ADDRESS);
            RateLimitResult result4 = rateLimitService.tryConsumeLogin(IP_ADDRESS);
            RateLimitResult result5 = rateLimitService.tryConsumeLogin(IP_ADDRESS);

            // Assert
            assertThat(result1.allowed()).isTrue();
            assertThat(result2.allowed()).isTrue();
            assertThat(result3.allowed()).isTrue();
            assertThat(result4.allowed()).isTrue();
            assertThat(result5.allowed()).isTrue();
            assertThat(result5.remainingTokens()).isEqualTo(0); // Último token
        }

        @Test
        @DisplayName("Deveria bloquear quando capacidade é excedida")
        void shouldBlock_WhenCapacityExceeded() {
            // Act - Consome 5 tokens (ok) + 1 adicional (bloqueado)
            rateLimitService.tryConsumeLogin(IP_ADDRESS);
            rateLimitService.tryConsumeLogin(IP_ADDRESS);
            rateLimitService.tryConsumeLogin(IP_ADDRESS);
            rateLimitService.tryConsumeLogin(IP_ADDRESS);
            rateLimitService.tryConsumeLogin(IP_ADDRESS);

            RateLimitResult blocked = rateLimitService.tryConsumeLogin(IP_ADDRESS);

            // Assert
            assertThat(blocked.allowed()).isFalse();
            assertThat(blocked.remainingTokens()).isEqualTo(0);
            assertThat(blocked.retryAfterSeconds()).isGreaterThan(0);
        }

        @Test
        @DisplayName("Deveria ter buckets independentes por IP")
        void shouldHaveIndependentBuckets_PerIP() {
            // Act
            RateLimitResult resultIp1 = rateLimitService.tryConsumeLogin(IP_ADDRESS);
            RateLimitResult resultIp2 = rateLimitService.tryConsumeLogin(ANOTHER_IP);

            // Assert - Ambos IPs devem ter tokens completos
            assertThat(resultIp1.allowed()).isTrue();
            assertThat(resultIp1.remainingTokens()).isEqualTo(4);

            assertThat(resultIp2.allowed()).isTrue();
            assertThat(resultIp2.remainingTokens()).isEqualTo(4);
        }

        @Test
        @DisplayName("Deveria decrementar tokens corretamente a cada chamada")
        void shouldDecrementTokens_CorrectlyPerCall() {
            // Act & Assert
            RateLimitResult result1 = rateLimitService.tryConsumeLogin(IP_ADDRESS);
            assertThat(result1.remainingTokens()).isEqualTo(4);

            RateLimitResult result2 = rateLimitService.tryConsumeLogin(IP_ADDRESS);
            assertThat(result2.remainingTokens()).isEqualTo(3);

            RateLimitResult result3 = rateLimitService.tryConsumeLogin(IP_ADDRESS);
            assertThat(result3.remainingTokens()).isEqualTo(2);
        }
    }

    // ========================================================================
    // TESTS: tryConsumeRegister()
    // ========================================================================

    @Nested
    @DisplayName("tryConsumeRegister() - Rate limiting de registro")
    class TryConsumeRegisterTests {

        @Test
        @DisplayName("Deveria permitir primeira requisição")
        void shouldAllow_FirstRequest() {
            // Act
            RateLimitResult result = rateLimitService.tryConsumeRegister(IP_ADDRESS);

            // Assert
            assertThat(result.allowed()).isTrue();
            assertThat(result.remainingTokens()).isEqualTo(2); // 3 - 1 = 2
        }

        @Test
        @DisplayName("Deveria permitir até 3 requisições (capacidade)")
        void shouldAllow_UpTo3Requests() {
            // Act
            RateLimitResult result1 = rateLimitService.tryConsumeRegister(IP_ADDRESS);
            RateLimitResult result2 = rateLimitService.tryConsumeRegister(IP_ADDRESS);
            RateLimitResult result3 = rateLimitService.tryConsumeRegister(IP_ADDRESS);

            // Assert
            assertThat(result1.allowed()).isTrue();
            assertThat(result2.allowed()).isTrue();
            assertThat(result3.allowed()).isTrue();
            assertThat(result3.remainingTokens()).isEqualTo(0);
        }

        @Test
        @DisplayName("Deveria bloquear 4ª requisição")
        void shouldBlock_FourthRequest() {
            // Act
            rateLimitService.tryConsumeRegister(IP_ADDRESS);
            rateLimitService.tryConsumeRegister(IP_ADDRESS);
            rateLimitService.tryConsumeRegister(IP_ADDRESS);
            RateLimitResult blocked = rateLimitService.tryConsumeRegister(IP_ADDRESS);

            // Assert
            assertThat(blocked.allowed()).isFalse();
            assertThat(blocked.retryAfterSeconds()).isGreaterThan(0);
        }
    }

    // ========================================================================
    // TESTS: tryConsumeForgotPassword()
    // ========================================================================

    @Nested
    @DisplayName("tryConsumeForgotPassword() - Rate limiting de esqueci senha")
    class TryConsumeForgotPasswordTests {

        @Test
        @DisplayName("Deveria permitir primeira requisição")
        void shouldAllow_FirstRequest() {
            // Act
            RateLimitResult result = rateLimitService.tryConsumeForgotPassword(IP_ADDRESS);

            // Assert
            assertThat(result.allowed()).isTrue();
            assertThat(result.remainingTokens()).isEqualTo(2);
        }

        @Test
        @DisplayName("Deveria bloquear após 3 tentativas")
        void shouldBlock_AfterThreeAttempts() {
            // Act
            rateLimitService.tryConsumeForgotPassword(IP_ADDRESS);
            rateLimitService.tryConsumeForgotPassword(IP_ADDRESS);
            rateLimitService.tryConsumeForgotPassword(IP_ADDRESS);
            RateLimitResult blocked = rateLimitService.tryConsumeForgotPassword(IP_ADDRESS);

            // Assert
            assertThat(blocked.allowed()).isFalse();
        }
    }

    // ========================================================================
    // TESTS: tryConsumeResendVerification()
    // ========================================================================

    @Nested
    @DisplayName("tryConsumeResendVerification() - Rate limiting de reenvio de verificação")
    class TryConsumeResendVerificationTests {

        @Test
        @DisplayName("Deveria permitir primeira requisição")
        void shouldAllow_FirstRequest() {
            // Act
            RateLimitResult result = rateLimitService.tryConsumeResendVerification(IP_ADDRESS);

            // Assert
            assertThat(result.allowed()).isTrue();
            assertThat(result.remainingTokens()).isEqualTo(2);
        }

        @Test
        @DisplayName("Deveria bloquear após 3 tentativas")
        void shouldBlock_AfterThreeAttempts() {
            // Act
            rateLimitService.tryConsumeResendVerification(IP_ADDRESS);
            rateLimitService.tryConsumeResendVerification(IP_ADDRESS);
            rateLimitService.tryConsumeResendVerification(IP_ADDRESS);
            RateLimitResult blocked = rateLimitService.tryConsumeResendVerification(IP_ADDRESS);

            // Assert
            assertThat(blocked.allowed()).isFalse();
        }
    }

    // ========================================================================
    // TESTS: tryConsumeGeneral()
    // ========================================================================

    @Nested
    @DisplayName("tryConsumeGeneral() - Rate limiting geral")
    class TryConsumeGeneralTests {

        @Test
        @DisplayName("Deveria permitir primeira requisição")
        void shouldAllow_FirstRequest() {
            // Act
            RateLimitResult result = rateLimitService.tryConsumeGeneral(IP_ADDRESS);

            // Assert
            assertThat(result.allowed()).isTrue();
            assertThat(result.remainingTokens()).isEqualTo(39);
        }

        @Test
        @DisplayName("Deveria permitir muitas requisições (capacidade alta)")
        void shouldAllow_ManyRequests() {
            for (int i = 0; i < 20; i++) {
                RateLimitResult result = rateLimitService.tryConsumeGeneral(IP_ADDRESS);
                assertThat(result.allowed()).isTrue();
            }

            RateLimitResult result = rateLimitService.tryConsumeGeneral(IP_ADDRESS);
            assertThat(result.allowed()).isTrue();
            assertThat(result.remainingTokens()).isEqualTo(19); // 40 - 21 = 19
        }
    }

    // ========================================================================
    // TESTS: Cenários de rate limiting
    // ========================================================================

    @Nested
    @DisplayName("Cenários de rate limiting")
    class RateLimitScenariosTests {

        @Test
        @DisplayName("Deveria isolar buckets entre diferentes endpoints")
        void shouldIsolateBuckets_BetweenEndpoints() {
            // Act - Esgota login
            rateLimitService.tryConsumeLogin(IP_ADDRESS);
            rateLimitService.tryConsumeLogin(IP_ADDRESS);
            rateLimitService.tryConsumeLogin(IP_ADDRESS);
            rateLimitService.tryConsumeLogin(IP_ADDRESS);
            rateLimitService.tryConsumeLogin(IP_ADDRESS);
            RateLimitResult loginBlocked = rateLimitService.tryConsumeLogin(IP_ADDRESS);

            // Tenta register (bucket diferente)
            RateLimitResult registerAllowed = rateLimitService.tryConsumeRegister(IP_ADDRESS);

            // Assert - Login bloqueado, mas register ainda funciona
            assertThat(loginBlocked.allowed()).isFalse();
            assertThat(registerAllowed.allowed()).isTrue();
        }

        @Test
        @DisplayName("Deveria retornar tempo de espera quando bloqueado")
        void shouldReturnWaitTime_WhenBlocked() {
            // Act - Esgota tokens
            rateLimitService.tryConsumeLogin(IP_ADDRESS);
            rateLimitService.tryConsumeLogin(IP_ADDRESS);
            rateLimitService.tryConsumeLogin(IP_ADDRESS);
            rateLimitService.tryConsumeLogin(IP_ADDRESS);
            rateLimitService.tryConsumeLogin(IP_ADDRESS);

            RateLimitResult blocked = rateLimitService.tryConsumeLogin(IP_ADDRESS);

            // Assert
            assertThat(blocked.allowed()).isFalse();
            assertThat(blocked.retryAfterSeconds()).isGreaterThan(0);
            assertThat(blocked.retryAfterSeconds()).isLessThanOrEqualTo(60); // Máximo 1 minuto
        }

        @Test
        @DisplayName("Deveria permitir requisições de IPs diferentes simultaneamente")
        void shouldAllow_RequestsFromDifferentIPs() {
            // Arrange
            String ip1 = "192.168.1.1";
            String ip2 = "192.168.1.2";
            String ip3 = "192.168.1.3";

            // Act
            RateLimitResult result1 = rateLimitService.tryConsumeLogin(ip1);
            RateLimitResult result2 = rateLimitService.tryConsumeLogin(ip2);
            RateLimitResult result3 = rateLimitService.tryConsumeLogin(ip3);

            // Assert - Todos devem ser permitidos
            assertThat(result1.allowed()).isTrue();
            assertThat(result2.allowed()).isTrue();
            assertThat(result3.allowed()).isTrue();
        }

        @Test
        @DisplayName("Deveria manter estado do bucket entre chamadas para o mesmo IP")
        void shouldMaintainBucketState_BetweenCallsForSameIP() {
            // Act
            RateLimitResult result1 = rateLimitService.tryConsumeLogin(IP_ADDRESS);
            RateLimitResult result2 = rateLimitService.tryConsumeLogin(IP_ADDRESS);
            RateLimitResult result3 = rateLimitService.tryConsumeLogin(IP_ADDRESS);

            // Assert - Tokens devem decrementar progressivamente
            assertThat(result1.remainingTokens()).isEqualTo(4);
            assertThat(result2.remainingTokens()).isEqualTo(3);
            assertThat(result3.remainingTokens()).isEqualTo(2);
        }

        @Test
        @DisplayName("Deveria ter capacidades diferentes para diferentes endpoints")
        void shouldHaveDifferentCapacities_ForDifferentEndpoints() {
            // Act
            RateLimitResult loginResult = rateLimitService.tryConsumeLogin(IP_ADDRESS);
            RateLimitResult registerResult = rateLimitService.tryConsumeRegister(ANOTHER_IP);
            RateLimitResult generalResult = rateLimitService.tryConsumeGeneral("192.168.1.3");

            // Assert - Capacidades diferentes
            assertThat(loginResult.remainingTokens()).isEqualTo(4); // capacity: 5
            assertThat(registerResult.remainingTokens()).isEqualTo(2); // capacity: 3
            assertThat(generalResult.remainingTokens()).isEqualTo(39); // capacity: 100
        }
    }

    // ========================================================================
    // TESTS: RateLimitResult
    // ========================================================================

    @Nested
    @DisplayName("RateLimitResult - Objeto de resposta")
    class RateLimitResultTests {

        @Test
        @DisplayName("Deveria criar resultado de sucesso corretamente")
        void shouldCreateSuccessResult_Correctly() {
            // Act
            RateLimitResult result = new RateLimitResult(true, 10, 0);

            // Assert
            assertThat(result.allowed()).isTrue();
            assertThat(result.remainingTokens()).isEqualTo(10);
            assertThat(result.retryAfterSeconds()).isEqualTo(0);
        }

        @Test
        @DisplayName("Deveria criar resultado de bloqueio corretamente")
        void shouldCreateBlockedResult_Correctly() {
            // Act
            RateLimitResult result = new RateLimitResult(false, 0, 60);

            // Assert
            assertThat(result.allowed()).isFalse();
            assertThat(result.remainingTokens()).isEqualTo(0);
            assertThat(result.retryAfterSeconds()).isEqualTo(60);
        }
    }
}
