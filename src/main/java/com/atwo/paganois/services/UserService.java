package com.atwo.paganois.services;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import com.atwo.paganois.dtos.UserDTO;
import com.atwo.paganois.entities.TokenType;
import com.atwo.paganois.entities.User;
import com.atwo.paganois.entities.VerificationToken;
import com.atwo.paganois.exceptions.AccountDisabledException;
import com.atwo.paganois.exceptions.EmailAlreadyTakenException;
import com.atwo.paganois.exceptions.LoggedUserAndChangeEmailTokenMismatchException;
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
    private VerificationService verificationService;

    UserService(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }

    @Transactional
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

    @Transactional
    public User registerUser(String username, String encodedPassword, String email) {
        User newUser = new User();
        newUser.setUsername(username);
        newUser.setPassword(encodedPassword);
        newUser.setRole(roleRepository.findByAuthority("ROLE_USER"));
        newUser.setEmail(email);

        User savedUser = save(newUser);
        return savedUser;
    }

    @Transactional
    public void setNewPassword(User user, String newPassword) {
        user.setPassword(passwordEncoder.encode(newPassword));
        userRepository.save(user);
    }

    @Transactional
    public void updatePassword(User user, String newPassword, String oldPassword) {
        String encodedOldPassword = passwordEncoder.encode(oldPassword);
        String encodedNewPassword = passwordEncoder.encode(newPassword);

        if (user.getPassword().equals(encodedOldPassword))
            throw new WrongPasswordException("Senha atual incorreta");

        user.setPassword(encodedNewPassword);
        userRepository.save(user);
    }

    public void requestEmailChange(User user, String newEmail) {
        validateNewEmail(user, newEmail);

        verificationService.sendEmailChangeVerification(user, newEmail);
    }

    public String confirmEmailChange(User user, String token) {
        VerificationToken verificationToken =
                verificationService.validateToken(token, TokenType.EMAIL_CHANGE);

        if (!verificationToken.getUser().getId().equals(user.getId()))
            throw new LoggedUserAndChangeEmailTokenMismatchException(
                    "Token de troca de email não pertence ao usuário autenticado");

        String newEmail = verificationToken.getPendingEmail();

        validateNewEmail(user, newEmail);

        updateEmail(user, newEmail);

        verificationService.deleteByUserIdAndType(user.getId(), TokenType.EMAIL_CHANGE);

        return newEmail;
    }

    public void validateNewEmail(User user, String newEmail) {
        if (user.getEmail().equalsIgnoreCase(newEmail)) {
            throw new EmailAlreadyTakenException("Este já é seu email atual");
        }

        if (userRepository.existsByEmailAndVerified(newEmail)) {
            throw new EmailAlreadyTakenException("Email já está em uso");
        }
    }

    @Transactional
    public void updateEmail(User user, String newEmail) {
        user.setEmail(newEmail);
        userRepository.save(user);
    }



    // TODO: adicionar exception no handler
    // TODO: terminar fluxo de update email
    // public void updateEmail(User user, String email){
    // if(userRepository.existsByEmail(email)) throw new EmailAlreadyTakenException("Email já em
    // uso");

    // }

}
