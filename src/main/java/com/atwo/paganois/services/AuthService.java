package com.atwo.paganois.services;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import com.atwo.paganois.dtos.LoginRequest;
import com.atwo.paganois.dtos.LoginResponse;
import com.atwo.paganois.dtos.RefreshRequest;
import com.atwo.paganois.dtos.RegisterRequest;
import com.atwo.paganois.dtos.RegisterResponse;
import com.atwo.paganois.entities.TokenType;
import com.atwo.paganois.entities.User;
import com.atwo.paganois.entities.VerificationToken;
import com.atwo.paganois.exceptions.InvalidTokenException;
import com.atwo.paganois.exceptions.UserAlreadyExistsException;
import com.atwo.paganois.exceptions.UserNotVerifiedOrNotEnabledException;
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
    private TokenRevocationService tokenRevocationService;

    @Autowired
    private JwtUtil jwtUtil;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Transactional
    public LoginResponse login(LoginRequest loginRequest) {
        Authentication authentication =
                authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(
                        loginRequest.username(), loginRequest.password()));

        User userDetails = (User) authentication.getPrincipal();
        if (!userDetails.isEmailVerified() || !userDetails.isEnabled())
            throw new UserNotVerifiedOrNotEnabledException("Conta desabilitada ou não verificada");

        String accessToken = jwtUtil.generateToken(userDetails);
        String refreshToken = jwtUtil.generateRefreshToken(userDetails);

        return new LoginResponse(accessToken, refreshToken);
    }

    @Transactional
    public LoginResponse refresh(RefreshRequest request) {
        String refreshToken = request.refreshToken();

        if (tokenRevocationService.isRevoked(refreshToken))
            throw new InvalidTokenException("Token já foi usado ou revogado");


        if (!jwtUtil.validateTokenWithVersion(refreshToken))
            throw new InvalidTokenException("Token inválido, expirado ou com versão desatualizada");

        String username = jwtUtil.extractUsername(refreshToken);
        UserDetails userDetails = userDetailsService.loadUserByUsername(username);

        tokenRevocationService.revokeToken(refreshToken);

        String newAccessToken = jwtUtil.generateToken(userDetails);
        String newRefreshToken = jwtUtil.generateRefreshToken(userDetails);

        return new LoginResponse(newAccessToken, newRefreshToken);
    }

    @Transactional
    public RegisterResponse register(RegisterRequest registerRequest) {
        if (userDetailsService.existsByUsername(registerRequest.getUsername())
                || userDetailsService.existsByEmailAndVerified(registerRequest.getEmail()))
            throw new UserAlreadyExistsException("Username ou email já está em uso");

        userDetailsService.deleteUnverifiedByEmail(registerRequest.getEmail());

        User savedUser = userService.registerUser(registerRequest.getUsername(),
                passwordEncoder.encode(registerRequest.getPassword()), registerRequest.getEmail());

        verificationService.sendEmailVerification(savedUser);
        return new RegisterResponse(savedUser.getId(), savedUser.getUsername(),
                savedUser.isEmailVerified());
    }

    @Transactional
    public void resendEmailVerification(String email) {
        if (!userDetailsService.existsByEmail(email))
            return;
        User user = userDetailsService.findByEmail(email);
        if (user.isEmailVerified())
            return;

        verificationService.sendEmailVerification(user);

    }

    @Transactional
    public void verifyEmail(String token) {
        VerificationToken verificationToken =
                verificationService.validateToken(token, TokenType.EMAIL_VERIFICATION);

        User user = verificationToken.getUser();
        user.setEmailVerified(true);
        userService.save(user);

        verificationService.deleteByUserIdAndType(user.getId(), verificationToken.getType());
    }

    @Transactional
    public void sendPasswordResetEmail(String email) {
        verificationService.sendPasswordReset(email);
    }

    @Transactional
    public void resetPassword(String token, String newPassword) {
        VerificationToken verificationToken =
                verificationService.validateToken(token, TokenType.PASSWORD_RESET);

        User user = verificationToken.getUser();

        userService.setNewPassword(user, newPassword);

        verificationService.deleteByUserIdAndType(user.getId(), verificationToken.getType());
    }

    /**
     * Logout normal - revoga apenas o token atual
     */
    @Transactional
    public void logout(String accessToken, String refreshToken) {
        // Valida se tokens são válidos antes de revogar
        if (!jwtUtil.validateToken(accessToken) || !jwtUtil.validateToken(refreshToken)) {
            throw new InvalidTokenException("Tokens inválidos");
        }

        // Revoga ambos os tokens
        tokenRevocationService.revokeTokenPair(accessToken, refreshToken);
    }

    /**
     * Logout global - revoga TODOS os tokens do usuário
     */
    @Transactional
    public void logoutAllDevices(String username) {
        tokenRevocationService.revokeAllUserTokens(username);
    }


}
