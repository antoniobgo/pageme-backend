package com.atwo.paganois.auth.repositories;

import java.time.Duration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Repository;

@Repository
public class RevokedTokenRepository {

    @Autowired
    private StringRedisTemplate redisTemplate;

    private static final String REVOKED_TOKEN_PREFIX = "auth:token:revoked:";
    private static final String USER_TOKEN_VERSION_PREFIX = "auth:user:token_version:";

    private static final Logger logger = LoggerFactory.getLogger(RevokedTokenRepository.class);


    public void save(String token, Duration ttl) {
        redisTemplate.opsForValue().set(REVOKED_TOKEN_PREFIX + token, "true", ttl);
        logger.debug("Token revoked with TTL: {} seconds", ttl.getSeconds());
    }

    public boolean exists(String token) {
        return Boolean.TRUE.equals(redisTemplate.hasKey(REVOKED_TOKEN_PREFIX + token));
    }

    public void delete(String token) {
        redisTemplate.delete(REVOKED_TOKEN_PREFIX + token);
        logger.debug("Deleted revoked token: {}", token);
    }

    public void incrementUserTokenVersion(String username) {
        redisTemplate.opsForValue().increment(USER_TOKEN_VERSION_PREFIX + username);
        logger.debug("Incremented {} token version: {}", username, getUserTokenVersion(username));
    }

    public Long getUserTokenVersion(String username) {
        String version = redisTemplate.opsForValue().get(USER_TOKEN_VERSION_PREFIX + username);
        return version != null ? Long.parseLong(version) : 0L;
    }
}
