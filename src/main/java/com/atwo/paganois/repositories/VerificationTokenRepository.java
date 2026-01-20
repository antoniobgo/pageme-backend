package com.atwo.paganois.repositories;

import com.atwo.paganois.entities.VerificationToken;
import com.atwo.paganois.entities.TokenType;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.Optional;

public interface VerificationTokenRepository extends JpaRepository<VerificationToken, String> {
    
    Optional<VerificationToken> findByToken(String token);
    
    void deleteByUserIdAndType(Long userId, TokenType type);
}