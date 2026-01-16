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
import com.atwo.paganois.entities.User;
import com.atwo.paganois.exceptions.UserAlreadyExistsException;
import com.atwo.paganois.repositories.RoleRepository;
import com.atwo.paganois.security.JwtUtil;

@Service
public class AuthService {

    @Autowired
    private CustomUserDetailsService userDetailsService;

    @Autowired
    private RoleRepository roleRepository;

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private JwtUtil jwtUtil;

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

        // TODO: isso nao deveria estar no global exception handler?
        // return ResponseEntity
        // .status(HttpStatus.UNAUTHORIZED)
        // .body(new ErrorResponse("Invalid refresh token"));
    }

    public RegisterResponse register(RegisterRequest registerRequest) {
        if (userDetailsService.existsByUsername(registerRequest.getUsername()))
            throw new UserAlreadyExistsException("Username já está em uso");

        User newUser = new User();
        newUser.setUsername(registerRequest.getUsername());
        newUser.setPassword(passwordEncoder.encode(registerRequest.getPassword()));
        newUser.setRole(roleRepository.findByAuthority("ROLE_USER"));
        newUser.setEnabled(true);

        User savedUser = userDetailsService.save(newUser);

        return new RegisterResponse(savedUser.getId(), savedUser.getUsername());
    }
}
