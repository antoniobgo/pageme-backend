package com.atwo.paganois.repositories;

import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import com.atwo.paganois.entities.TokenType;
import com.atwo.paganois.entities.VerificationToken;

public interface VerificationTokenRepository extends JpaRepository<VerificationToken, String> {

    Optional<VerificationToken> findByToken(String token);

    @Modifying
    void deleteByUserIdAndType(Long userId, TokenType type);
}
