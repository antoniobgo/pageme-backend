package com.atwo.paganois.services;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.atwo.paganois.dtos.LoginRequest;
import com.atwo.paganois.dtos.LoginResponse;
import com.atwo.paganois.dtos.RefreshRequest;
import com.atwo.paganois.dtos.RegisterRequest;
import com.atwo.paganois.dtos.RegisterResponse;
import com.atwo.paganois.entities.TokenType;
import com.atwo.paganois.entities.User;
import com.atwo.paganois.entities.VerificationToken;
import com.atwo.paganois.exceptions.UserAlreadyExistsException;
import com.atwo.paganois.security.JwtUtil;

@Service
public class AuthService {

    @Autowired
    private CustomUserDetailsService userDetailsService;

    @Autowired
    private UserService userService;

    @Autowired
    private VerificationService verificationService;

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private JwtUtil jwtUtil;

    @Autowired
    private PasswordEncoder passwordEncoder;

    public LoginResponse login(LoginRequest loginRequest) {
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        loginRequest.username(),
                        loginRequest.password()));

        UserDetails userDetails = (UserDetails) authentication.getPrincipal();

        String accessToken = jwtUtil.generateToken(userDetails);
        String refreshToken = jwtUtil.generateRefreshToken(userDetails);

        return new LoginResponse(accessToken, refreshToken);
    }

    public LoginResponse refresh(RefreshRequest request) {
        String refreshToken = request.refreshToken();

        // validate and --todo:-- throw exception
        jwtUtil.validateToken(refreshToken);
        String username = jwtUtil.extractUsername(refreshToken);
        UserDetails userDetails = userDetailsService.loadUserByUsername(username);
        String newAccessToken = jwtUtil.generateToken(userDetails);

        return new LoginResponse(newAccessToken, refreshToken);
    }

    public RegisterResponse register(RegisterRequest registerRequest) {
        if (userDetailsService.existsByUsername(registerRequest.getUsername())
                || userDetailsService.existsByEmail(registerRequest.getEmail()))
            throw new UserAlreadyExistsException("Username ou email já está em uso");

        User savedUser = userService.registerUser(registerRequest.getUsername(),
                passwordEncoder.encode(registerRequest.getPassword()),
                registerRequest.getEmail());

        verificationService.sendEmailVerification(savedUser);

        return new RegisterResponse(savedUser.getId(), savedUser.getUsername(), savedUser.isEmailVerified());
    }

    public void resendEmailVerification(String email) {
        if (!userDetailsService.existsByEmail(email))
            throw new RuntimeException("Email não encontrado");

        User user = userDetailsService.findByEmail(email);
        if (user.isEmailVerified())
            throw new RuntimeException("Usuário com email já verificado");

        verificationService.sendEmailVerification(user);

    }

    public void verifyEmail(String token) {
        VerificationToken verificationToken = verificationService.validateToken(token, TokenType.EMAIL_VERIFICATION);

        User user = verificationToken.getUser();
        user.setEmailVerified(true);
        userService.save(user);

        verificationService.deleteToken(verificationToken);
    }

    public void sendPasswordResetEmail(String email) {
        verificationService.sendPasswordReset(email);
    }

    public void resetPassword(String token, String newPassword) {
        VerificationToken tokenEntity = verificationService.validateToken(token, TokenType.PASSWORD_RESET);

        User user = tokenEntity.getUser();

        userService.setNewPassword(user, passwordEncoder.encode(newPassword));
    }
}
