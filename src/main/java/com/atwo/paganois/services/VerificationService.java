package com.atwo.paganois.services;

import java.time.LocalDateTime;
import java.util.Optional;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
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

    private static final Logger logger = LoggerFactory.getLogger(VerificationService.class);

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

        emailService.sendSimpleEmail(email, "Resetar senha - Paganois",
                "Utilize esse token para resetar sua senha:\n" + token);
    }

    // TODO: adicionar e tratar exceptions (MessagingException)
    // TODO: deletar tokens antigos
    @Transactional
    public void sendEmailVerification(User user) {
        logger.debug("Iniciando processo de envio de email de verificação");
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

    @Transactional
    public void sendEmailChangeVerification(User user, String newEmail) {
        tokenRepository.deleteByUserIdAndType(user.getId(), TokenType.EMAIL_CHANGE);

        String token = UUID.randomUUID().toString();

        VerificationToken changeToken = new VerificationToken();
        changeToken.setToken(token);
        changeToken.setUser(user);
        changeToken.setType(TokenType.EMAIL_CHANGE);
        changeToken.setPendingEmail(newEmail);
        changeToken.setExpiryDate(LocalDateTime.now().plusHours(24));
        tokenRepository.save(changeToken);

        String confirmationUrl = baseUrl + "/api/users/me/email/confirm?token=" + token;

        emailService.sendSimpleEmail(newEmail, "Confirme mudança de email - Paganois",
                String.format(
                        "Você solicitou a mudança de email da sua conta Paganois.\n\n"
                                + "Email atual: %s\n" + "Novo email: %s\n\n"
                                + "Clique no link para confirmar: %s\n\n"
                                + "Se você não solicitou esta mudança, ignore este email.",
                        user.getEmail(), newEmail, confirmationUrl));
    }

    public void deleteToken(VerificationToken verificationToken) {
        tokenRepository.delete(verificationToken);
    }

    @Transactional
    public void deleteByUserIdAndType(Long id, TokenType type) {
        tokenRepository.deleteByUserIdAndType(id, type);
    }

}
