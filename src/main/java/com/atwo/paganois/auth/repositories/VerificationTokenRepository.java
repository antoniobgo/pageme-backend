package com.atwo.paganois.auth.repositories;

import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;
import com.atwo.paganois.auth.entities.TokenType;
import com.atwo.paganois.auth.entities.VerificationToken;

public interface VerificationTokenRepository extends JpaRepository<VerificationToken, String> {

    Optional<VerificationToken> findByToken(String token);

    void deleteByUserIdAndType(Long userId, TokenType type);

}
