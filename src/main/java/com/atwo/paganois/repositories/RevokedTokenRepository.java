package com.atwo.paganois.repositories;

import java.time.Duration;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Repository;

@Repository
public class RevokedTokenRepository {

    @Autowired
    private RedisTemplate<String, String> redisTemplate;

    private static final String REVOKED_PREFIX = "revoked:";
    private static final String USER_VERSION_PREFIX = "user:token:version:";

    public void save(String token, Duration ttl) {
        redisTemplate.opsForValue().set(REVOKED_PREFIX + token, "true", ttl);
    }

    public boolean exists(String token) {
        return Boolean.TRUE.equals(redisTemplate.hasKey(REVOKED_PREFIX + token));
    }

    public void delete(String token) {
        redisTemplate.delete(REVOKED_PREFIX + token);
    }

    public Long incrementUserTokenVersion(String username) {
        return redisTemplate.opsForValue().increment(USER_VERSION_PREFIX + username);
    }

    public Long getUserTokenVersion(String username) {
        String version = redisTemplate.opsForValue().get(USER_VERSION_PREFIX + username);
        return version != null ? Long.parseLong(version) : 0L;
    }
}
