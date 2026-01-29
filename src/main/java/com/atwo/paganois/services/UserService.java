package com.atwo.paganois.services;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import com.atwo.paganois.dtos.UserDTO;
import com.atwo.paganois.entities.User;
import com.atwo.paganois.exceptions.AccountDisabledException;
import com.atwo.paganois.exceptions.UserNotFoundException;
import com.atwo.paganois.exceptions.WrongPasswordException;
import com.atwo.paganois.repositories.RoleRepository;
import com.atwo.paganois.repositories.UserRepository;

@Service
public class UserService {

    private final PasswordEncoder passwordEncoder;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private RoleRepository roleRepository;

    @Autowired
    private AuthenticationManager authenticationManager;

    UserService(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }

    public User save(User user) {
        return userRepository.save(user);
    }

    public UserDTO getAuthenticatedUserProfile(User user) {
        if (!user.isEnabled())
            throw new AccountDisabledException("Conta desativada");
        if (!userRepository.existsByUsername(user.getUsername()))
            throw new UserNotFoundException("Usuário não encontrado");

        return new UserDTO(user);
    }

    public User registerUser(String username, String encodedPassword, String email) {
        User newUser = new User();
        newUser.setUsername(username);
        newUser.setPassword(encodedPassword);
        newUser.setRole(roleRepository.findByAuthority("ROLE_USER"));
        newUser.setEmail(email);

        User savedUser = save(newUser);
        return savedUser;
    }

    public void setNewPassword(User user, String newPassword) {
        user.setPassword(passwordEncoder.encode(newPassword));
        userRepository.save(user);
    }

    @Transactional
    public void updatePassword(User user, String newPassword, String oldPassword) {
        String encodedOldPassword = passwordEncoder.encode(oldPassword);
        String encodedNewPassword = passwordEncoder.encode(newPassword);

        if (user.getPassword().equals(passwordEncoder.encode(encodedOldPassword)))
            throw new WrongPasswordException("Senha atual incorreta");

        user.setPassword(encodedNewPassword);
        userRepository.save(user);
    }

    // TODO: adicionar exception no handler
    // TODO: terminar fluxo de update email
    // public void updateEmail(User user, String email){
    // if(userRepository.existsByEmail(email)) throw new EmailAlreadyTakenException("Email já em
    // uso");

    // }

}
