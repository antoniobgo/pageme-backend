package com.atwo.paganois.services;

import java.time.Duration;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

@Service
public class RefreshTokenService {

    @Autowired
    private RedisTemplate<String, String> redisTemplate;

    @Value("${jwt.refresh-expiration}")
    private Long refreshExpiration;

    private static final String REVOKED_PREFIX = "revoked:";

    public void revokeToken(String token) {
        // Salva no Redis com TTL igual ao tempo de expiração do token
        Duration ttl = Duration.ofMillis(refreshExpiration);
        redisTemplate.opsForValue().set(REVOKED_PREFIX + token, "true", ttl);
    }

    public boolean isRevoked(String token) {
        return Boolean.TRUE.equals(redisTemplate.hasKey(REVOKED_PREFIX + token));
    }

    public void revokeAllUserTokens(String username) {
        // Para invalidar todos os tokens de um usuário (logout completo)
        redisTemplate.opsForSet().add("revoked:user:" + username, username);
    }
}
