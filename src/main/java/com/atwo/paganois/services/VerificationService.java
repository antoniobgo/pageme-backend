package com.atwo.paganois.services;

import java.time.LocalDateTime;
import java.util.Optional;
import java.util.UUID;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import com.atwo.paganois.entities.TokenType;
import com.atwo.paganois.entities.User;
import com.atwo.paganois.entities.VerificationToken;
import com.atwo.paganois.repositories.VerificationTokenRepository;

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

    @Transactional
    public void sendPasswordReset(String email) {
        // TODO: adicionar e tratar exceptions (MessagingException)
        System.out.println("email: " + email);
        Optional<User> optionalUser = userService.findByEmail(email);
        if (optionalUser.isEmpty())
            return;

        User user = optionalUser.get();

        // Remove tokens antigos
        tokenRepository.deleteByUserIdAndType(user.getId(), TokenType.PASSWORD_RESET);

        // Gera novo token
        String token = UUID.randomUUID().toString();

        VerificationToken resetToken = new VerificationToken();
        resetToken.setToken(token);
        resetToken.setUser(user);
        resetToken.setType(TokenType.PASSWORD_RESET);
        resetToken.setExpiryDate(LocalDateTime.now().plusHours(1));
        tokenRepository.save(resetToken);

        // Monta URL de reset
        String resetUrl = baseUrl + "/auth/reset-password?token=" + token;

        // Envia email
        emailService.sendSimpleEmail(
                email,
                "Resetar senha - Paganois",
                "Clique no link a seguir para resetar sua senha: \n" + resetUrl
                        + "\n PS: testar via API Clients (Postman, Insonmia) caso sem frontend");
    }

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
                user.getEmail(),
                "Confirme seu email - Paganois",
                "Por favor, confirme seu email clicando no link: \n" + confirmationUrl);
    }

    // TODO: tratar as excessões (e especializar)
    @Transactional
    public VerificationToken validateToken(String token, TokenType type) {
        VerificationToken tokenEntity = tokenRepository
                .findByToken(token)
                .orElseThrow(() -> new RuntimeException("Token inválido"));
        if (tokenEntity.getType() != type)
            throw new RuntimeException("Token inválido");

        if (tokenEntity.isExpired()) {
            throw new RuntimeException("Token expirado");
        }

        return tokenEntity;
    }

    public void deleteToken(VerificationToken verificationToken) {
        tokenRepository.delete(verificationToken);
    }

}