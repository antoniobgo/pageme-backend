package com.atwo.paganois.services;

import java.time.Duration;
import java.util.concurrent.TimeUnit;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import com.atwo.paganois.config.RateLimitConfig;
import com.atwo.paganois.config.RateLimitConfig.EndpointLimit;
import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import io.github.bucket4j.Bandwidth;
import io.github.bucket4j.Bucket;
import io.github.bucket4j.ConsumptionProbe;

/**
 * Serviço de Rate Limiting usando Bucket4j + Caffeine Cache
 * 
 * Funciona com o algoritmo "Token Bucket": - Cada IP tem um "balde" com tokens - Cada request
 * consome 1 token - Tokens são reabastecidos periodicamente - Se não há tokens, request é rejeitado
 * 
 * Exemplo: Login com capacity=5, refill=5/minuto - Usuário pode fazer 5 requests imediatamente -
 * Após esgotar, precisa esperar tokens recarregarem - A cada minuto, 5 novos tokens são adicionados
 * (até o máximo de 5)
 */
@Service
public class RateLimitService {

    private static final Logger logger = LoggerFactory.getLogger(RateLimitService.class);

    private final RateLimitConfig config;

    // Cache separado para cada tipo de endpoint (IP -> Bucket)
    private final Cache<String, Bucket> loginBuckets;
    private final Cache<String, Bucket> registerBuckets;
    private final Cache<String, Bucket> forgotPasswordBuckets;
    private final Cache<String, Bucket> resendVerificationBuckets;
    private final Cache<String, Bucket> generalBuckets;

    public RateLimitService(RateLimitConfig config) {
        this.config = config;

        // Configura caches com expiração automática
        // Quando um IP fica inativo, o bucket é removido (economia de memória)
        this.loginBuckets = buildCache();
        this.registerBuckets = buildCache();
        this.forgotPasswordBuckets = buildCache();
        this.resendVerificationBuckets = buildCache();
        this.generalBuckets = buildCache();
    }

    private Cache<String, Bucket> buildCache() {
        return Caffeine.newBuilder().maximumSize(config.getCacheMaxSize())
                .expireAfterAccess(config.getCacheExpireMinutes(), TimeUnit.MINUTES).build();
    }

    /**
     * Verifica se o request deve ser permitido para /auth/login
     */
    public RateLimitResult tryConsumeLogin(String ip) {
        return tryConsume(ip, loginBuckets, config.getLogin(), "login");
    }

    /**
     * Verifica se o request deve ser permitido para /auth/register
     */
    public RateLimitResult tryConsumeRegister(String ip) {
        return tryConsume(ip, registerBuckets, config.getRegister(), "register");
    }

    /**
     * Verifica se o request deve ser permitido para /auth/forgot-password
     */
    public RateLimitResult tryConsumeForgotPassword(String ip) {
        return tryConsume(ip, forgotPasswordBuckets, config.getForgotPassword(), "forgot-password");
    }

    /**
     * Verifica se o request deve ser permitido para /auth/resend-verification
     */
    public RateLimitResult tryConsumeResendVerification(String ip) {
        return tryConsume(ip, resendVerificationBuckets, config.getResendVerification(),
                "resend-verification");
    }

    /**
     * Verifica se o request deve ser permitido para endpoints gerais
     */
    public RateLimitResult tryConsumeGeneral(String ip) {
        return tryConsume(ip, generalBuckets, config.getGeneral(), "general");
    }

    /**
     * Lógica principal de rate limiting
     */
    private RateLimitResult tryConsume(String ip, Cache<String, Bucket> cache, EndpointLimit limit,
            String endpointName) {

        // Obtém ou cria bucket para este IP
        Bucket bucket = cache.get(ip, key -> createBucket(limit));

        // Tenta consumir 1 token
        ConsumptionProbe probe = bucket.tryConsumeAndReturnRemaining(1);

        if (probe.isConsumed()) {
            logger.debug("Rate limit OK para IP {} no endpoint {}: {} tokens restantes", ip,
                    endpointName, probe.getRemainingTokens());

            return new RateLimitResult(true, probe.getRemainingTokens(), 0);
        } else {
            long waitTimeSeconds = probe.getNanosToWaitForRefill() / 1_000_000_000;

            logger.warn("Rate limit EXCEDIDO para IP {} no endpoint {}: aguardar {} segundos", ip,
                    endpointName, waitTimeSeconds);

            return new RateLimitResult(false, 0, waitTimeSeconds);
        }
    }

    /**
     * Cria um novo bucket com a configuração especificada
     */
    private Bucket createBucket(EndpointLimit limit) {
        Bandwidth bandwidth = Bandwidth.builder().capacity(limit.getCapacity())
                .refillGreedy(limit.getRefillTokens(), Duration.ofMinutes(limit.getRefillMinutes()))
                .build();

        return Bucket.builder().addLimit(bandwidth).build();
    }

    /**
     * Resultado da verificação de rate limit
     */
    public record RateLimitResult(boolean allowed, long remainingTokens, long retryAfterSeconds) {
    }
}
