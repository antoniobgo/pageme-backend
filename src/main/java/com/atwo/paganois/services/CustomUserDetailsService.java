package com.atwo.paganois.services;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.atwo.paganois.dtos.UserDTO;
import com.atwo.paganois.entities.User;
import com.atwo.paganois.exceptions.AccountDisabledException;
import com.atwo.paganois.exceptions.UserNotFoundException;
import com.atwo.paganois.repositories.UserRepository;

@Service
public class CustomUserDetailsService implements UserDetailsService {

    @Autowired
    private UserRepository userRepository;

    public User save(User user) {
        return userRepository.save(user);
    }

    public boolean existsByUsername(String username) {
        return userRepository.existsByUsername(username);
    }

    public UserDTO getAuthenticatedUserProfile(UserDetails user) {
        if (!user.isEnabled())
            throw new AccountDisabledException("Conta desativada");
        if (!existsByUsername(user.getUsername()))
            throw new UserNotFoundException("Usuário não encontrado");

        return new UserDTO(user);
    }

    @Override
    public User loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found: " + username));
        return user;
        // ✅ Como salvamos com ROLE_ no banco, usamos .authorities()
        // return org.springframework.security.core.userdetails.User.builder()
        // .username(user.getUsername())
        // .password(user.getPassword())
        // .authorities(user.getRole()) // ✅ Corrigido! Usa authorities com ROLE_ já
        // incluso
        // .accountExpired(false)
        // .accountLocked(false)
        // .credentialsExpired(false)
        // .disabled(!user.isEnabled())
        // .build();
    }
}