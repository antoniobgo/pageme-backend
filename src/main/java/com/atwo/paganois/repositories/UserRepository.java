package com.atwo.paganois.repositories;

import java.time.LocalDateTime;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;
import com.atwo.paganois.entities.User;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {
    Optional<User> findByUsername(String username);

    Optional<User> findByEmail(String email);

    boolean existsByUsername(String username);

    boolean existsByEmail(String email);

    @Query("SELECT CASE WHEN COUNT(u) > 0 THEN true ELSE false END FROM User u WHERE u.email = :email AND u.emailVerified = true")
    boolean existsByEmailAndVerified(@Param("email") String email);

    @Modifying
    @Query("DELETE FROM User u WHERE u.email = :email AND u.emailVerified = false")
    void deleteUnverifiedByEmail(String email);

    @Modifying
    @Query("DELETE FROM User u WHERE u.emailVerified = false AND u.createdAt < :expiryDate")
    int deleteExpiredUnverifiedUsers(LocalDateTime expiryDate);
}
