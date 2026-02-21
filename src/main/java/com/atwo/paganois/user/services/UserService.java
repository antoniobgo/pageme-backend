package com.atwo.paganois.user.services;

import java.time.LocalDateTime;
import java.util.Optional;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import com.atwo.paganois.auth.entities.TokenType;
import com.atwo.paganois.auth.entities.VerificationToken;
import com.atwo.paganois.auth.exceptions.AccountDisabledException;
import com.atwo.paganois.auth.exceptions.EmailAlreadyTakenException;
import com.atwo.paganois.auth.exceptions.LoggedUserAndChangeEmailTokenMismatchException;
import com.atwo.paganois.auth.exceptions.WrongPasswordException;
import com.atwo.paganois.auth.services.VerificationService;
import com.atwo.paganois.user.dtos.UserDTO;
import com.atwo.paganois.user.entities.User;
import com.atwo.paganois.user.exceptions.UserNotFoundException;
import com.atwo.paganois.user.repositories.RoleRepository;
import com.atwo.paganois.user.repositories.UserRepository;

@Service
public class UserService {

    private final PasswordEncoder passwordEncoder;

    private UserRepository userRepository;

    private RoleRepository roleRepository;

    private VerificationService verificationService;

    UserService(PasswordEncoder passwordEncoder, UserRepository userRepository,
            RoleRepository roleRepository, VerificationService verificationService) {
        this.passwordEncoder = passwordEncoder;
        this.userRepository = userRepository;
        this.roleRepository = roleRepository;
        this.verificationService = verificationService;
    }

    @Transactional
    public User save(User user) {
        return userRepository.save(user);
    }

    public UserDTO getAuthenticatedUserProfile(User user) {
        // TODO: pensar se necessário verificar isso aqui ou apenas no login
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

        if (!user.getPassword().equals(encodedOldPassword))
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

    @Transactional(readOnly = true)
    public User loadByUsername(String username) {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found: " + username));
        return user;
    }

    @Transactional
    public void updateEmail(User user, String newEmail) {
        user.setEmail(newEmail);
        userRepository.save(user);
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
