package com.atwo.paganois.services;

import java.time.LocalDateTime;
import java.util.UUID;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import com.atwo.paganois.entities.TokenType;
import com.atwo.paganois.entities.User;
import com.atwo.paganois.entities.VerificationToken;
import com.atwo.paganois.repositories.VerificationTokenRepository;

import jakarta.mail.MessagingException;
import jakarta.transaction.Transactional;

@Service
public class VerificationService {

    @Autowired
    private VerificationTokenRepository tokenRepository;

    @Autowired
    private CustomUserDetailsService userService;

    @Autowired
    private EmailService emailService;

    @Value("${app.base-url:http://localhost:8080}")
    private String baseUrl;

    // TODO: adicionar e tratar exceptions (MessagingException)
    @Transactional
    public void sendEmailVerification(User user) {
        // Gera token único
        String token = UUID.randomUUID().toString();
        
        // Salva token no banco
        VerificationToken verificationToken = new VerificationToken();
        verificationToken.setToken(token);
        verificationToken.setUser(user);
        verificationToken.setType(TokenType.EMAIL_VERIFICATION);
        verificationToken.setExpiryDate(LocalDateTime.now().plusHours(24));
        tokenRepository.save(verificationToken);
        
        // Monta URL de confirmação
        String confirmationUrl = baseUrl + "/auth/verify-email?token=" + token;
        
        
        // Envia email
        emailService.sendSimpleEmail(
            user.getEmail(), // assumindo que username é o email
            "Confirme seu email - Paganois",
            "Por favor, confirme seu email clicando no link: \n"+confirmationUrl
        );
    }
    
    @Transactional
    public boolean verifyEmail(String token) {
        VerificationToken verificationToken = tokenRepository
            .findByToken(token)
            .orElseThrow(() -> new RuntimeException("Token inválido"));
        
        if (verificationToken.isExpired()) {
            throw new RuntimeException("Token expirado");
        }
        
        User user = verificationToken.getUser();
        user.setEmailVerified(true);
        userService.save(user);
        
        tokenRepository.delete(verificationToken);
        
        return true;
    }
}