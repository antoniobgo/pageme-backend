package com.atwo.paganois.services;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.atwo.paganois.entities.User;
import com.atwo.paganois.repositories.UserRepository;

@Service
public class CustomUserDetailsService implements UserDetailsService {

    @Autowired
    private UserRepository userRepository;

    @Override
    public User loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found: " + username));
        return user;
        // ✅ Como salvamos com ROLE_ no banco, usamos .authorities()
        // return org.springframework.security.core.userdetails.User.builder()
        //         .username(user.getUsername())
        //         .password(user.getPassword())
        //         .authorities(user.getRole()) // ✅ Corrigido! Usa authorities com ROLE_ já incluso
        //         .accountExpired(false)
        //         .accountLocked(false)
        //         .credentialsExpired(false)
        //         .disabled(!user.isEnabled())
        //         .build();
    }
}