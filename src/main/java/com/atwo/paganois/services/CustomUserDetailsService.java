package com.atwo.paganois.services;

import java.time.LocalDateTime;
import java.util.Optional;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import com.atwo.paganois.entities.User;
import com.atwo.paganois.exceptions.UserNotFoundException;
import com.atwo.paganois.repositories.UserRepository;

@Service
public class CustomUserDetailsService implements UserDetailsService {

    @Autowired
    private UserRepository userRepository;

    @Transactional(readOnly = true)
    @Override
    public User loadUserByUsername(String username) {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found: " + username));
        return user;
    }

    @Transactional(readOnly = true)
    public User findByEmail(String email) {
        return userRepository.findByEmail(email)
                .orElseThrow(() -> new UserNotFoundException("User not found: " + email));
    }

    @Transactional(readOnly = true)
    public Optional<User> findByEmailOptional(String email) {
        return userRepository.findByEmail(email);
    }

    @Transactional(readOnly = true)
    public boolean existsByUsername(String username) {
        return userRepository.existsByUsername(username);
    }

    @Transactional(readOnly = true)
    public boolean existsByEmail(String email) {
        return userRepository.existsByEmail(email);
    }

    @Transactional(readOnly = true)
    public boolean existsByEmailAndVerified(String email) {
        return userRepository.existsByEmailAndVerified(email);
    }

    @Transactional
    public void deleteUnverifiedByEmail(String email) {
        userRepository.deleteUnverifiedByEmail(email);
    }

    @Transactional
    public int cleanupExpiredUnverifiedUsers(int daysToExpire) {
        LocalDateTime expiryDate = LocalDateTime.now().minusDays(daysToExpire);
        return userRepository.deleteExpiredUnverifiedUsers(expiryDate);
    }


}
