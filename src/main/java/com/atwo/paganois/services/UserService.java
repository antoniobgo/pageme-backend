package com.atwo.paganois.services;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.atwo.paganois.dtos.UserDTO;
import com.atwo.paganois.entities.User;
import com.atwo.paganois.exceptions.AccountDisabledException;
import com.atwo.paganois.exceptions.UserNotFoundException;
import com.atwo.paganois.repositories.RoleRepository;
import com.atwo.paganois.repositories.UserRepository;

@Service
public class UserService {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private RoleRepository roleRepository;

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

    public void setNewPassword(User user, String encodedPassword) {
        user.setPassword(encodedPassword);
        userRepository.save(user);
    }

}
