package com.atwo.paganois.services;

import java.time.Duration;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import com.atwo.paganois.repositories.RevokedTokenRepository;

/**
 * Gerencia revogação de tokens JWT
 * 
 * Responsabilidades: - Revogar tokens individuais (rotation no /refresh) - Revogar todos os tokens
 * de um usuário (logout global) - Verificar se token está revogado
 */
@Service
public class TokenRevocationService {

    @Autowired
    private RevokedTokenRepository revokedTokenRepository;

    @Value("${jwt.refresh-expiration}")
    private Long refreshExpiration;

    @Value("${jwt.expiration}")
    private Long accessExpiration;

    /**
     * Revoga um refresh token específico Usado no fluxo de refresh (token rotation)
     */
    public void revokeToken(String token) {
        Duration ttl = Duration.ofMillis(refreshExpiration);
        revokedTokenRepository.save(token, ttl);
    }

    /**
     * Revoga access token e refresh token Usado no logout normal
     */
    public void revokeTokenPair(String accessToken, String refreshToken) {
        Duration accessTtl = Duration.ofMillis(accessExpiration);
        Duration refreshTtl = Duration.ofMillis(refreshExpiration);

        revokedTokenRepository.save(accessToken, accessTtl);
        revokedTokenRepository.save(refreshToken, refreshTtl);
    }

    /**
     * Verifica se token foi revogado
     */
    public boolean isRevoked(String token) {
        return revokedTokenRepository.exists(token);
    }

    /**
     * Revoga todos os tokens de um usuário Incrementa versão → invalida todos os tokens antigos
     * 
     * Usado para: - Logout de todos os dispositivos - Mudança de senha - Comprometimento de conta
     */
    public void revokeAllUserTokens(String username) {
        revokedTokenRepository.incrementUserTokenVersion(username);
    }

    /**
     * Obtém versão atual dos tokens do usuário Usado pelo JwtUtil para validar token version
     */
    public Long getCurrentUserTokenVersion(String username) {
        return revokedTokenRepository.getUserTokenVersion(username);
    }
}
