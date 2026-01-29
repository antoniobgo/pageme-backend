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
import com.atwo.paganois.exceptions.ExpiredTokenException;
import com.atwo.paganois.exceptions.InvalidTokenTypeException;
import com.atwo.paganois.exceptions.TokenNotFoundException;
import com.atwo.paganois.repositories.VerificationTokenRepository;
import jakarta.transaction.Transactional;

@Service
public class VerificationService {

    @Autowired
    private VerificationTokenRepository tokenRepository;

    @Autowired
    private CustomUserDetailsService userDetailsService;

    @Autowired
    private EmailService emailService;

    @Value("${app.base-url:http://localhost:8080}")
    private String baseUrl;

    @Transactional
    public void sendPasswordReset(String email) {
        Optional<User> userOptional = userDetailsService.findByEmailOptional(email);
        if (userOptional.isEmpty())
            return;

        User user = userOptional.get();

        tokenRepository.deleteByUserIdAndType(user.getId(), TokenType.PASSWORD_RESET);

        String token = UUID.randomUUID().toString();

        VerificationToken resetToken = new VerificationToken();
        resetToken.setToken(token);
        resetToken.setUser(user);
        resetToken.setType(TokenType.PASSWORD_RESET);
        resetToken.setExpiryDate(LocalDateTime.now().plusHours(1));
        tokenRepository.save(resetToken);

        String resetUrl = baseUrl + "/auth/reset-password?token=" + token;

        emailService.sendSimpleEmail(email, "Resetar senha - Paganois",
                "Clique no link a seguir para resetar sua senha: \n" + resetUrl
                        + "\n PS: testar via API Clients (Postman, Insonmia) caso sem frontend");
    }

    // TODO: adicionar e tratar exceptions (MessagingException)
    @Transactional
    public void sendEmailVerification(User user) {

        tokenRepository.deleteByUserIdAndType(user.getId(), TokenType.EMAIL_VERIFICATION);

        String token = UUID.randomUUID().toString();

        VerificationToken verificationToken = new VerificationToken();
        verificationToken.setToken(token);
        verificationToken.setUser(user);
        verificationToken.setType(TokenType.EMAIL_VERIFICATION);
        verificationToken.setExpiryDate(LocalDateTime.now().plusHours(24));
        tokenRepository.save(verificationToken);

        String confirmationUrl = baseUrl + "/auth/verify-email?token=" + token;

        emailService.sendSimpleEmail(user.getEmail(), "Confirme seu email - Paganois",
                "Por favor, confirme seu email clicando no link: \n" + confirmationUrl);
    }

    @Transactional
    public VerificationToken validateToken(String token, TokenType type) {
        VerificationToken tokenEntity = tokenRepository.findByToken(token)
                .orElseThrow(() -> new TokenNotFoundException("Token não encontrado"));
        if (tokenEntity.getType() != type)
            throw new InvalidTokenTypeException("Token com tipo inválido");

        if (tokenEntity.isExpired()) {
            throw new ExpiredTokenException("Token expirado");
        }

        return tokenEntity;
    }

    public void deleteToken(VerificationToken verificationToken) {
        tokenRepository.delete(verificationToken);
    }

}
