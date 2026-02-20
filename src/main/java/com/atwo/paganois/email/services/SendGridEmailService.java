package com.atwo.paganois.email.services;

import java.io.IOException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Primary;
import org.springframework.context.annotation.Profile;
import org.springframework.mail.MailSendException;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;
import com.sendgrid.Method;
import com.sendgrid.Request;
import com.sendgrid.Response;
import com.sendgrid.SendGrid;
import com.sendgrid.helpers.mail.Mail;
import com.sendgrid.helpers.mail.objects.Content;
import com.sendgrid.helpers.mail.objects.Email;

@Service
@Primary
@Profile("prod")
public class SendGridEmailService implements EmailService {

    private static final Logger logger = LoggerFactory.getLogger(SmtpEmailService.class);

    @Value("${sendgrid.api.key}")
    private String apiKey;

    @Value("${spring.mail.username}")
    private String fromEmail;

    private final SendGrid sendGrid;

    public SendGridEmailService() {
        sendGrid = new SendGrid(apiKey);
    }

    @Override
    @Async("emailExecutor")
    public void sendSimpleEmail(String to, String subject, String text) {
        Content content = new Content("text/plain", text);
        sendEmail(to, subject, content);
    }

    @Override
    @Async("emailExecutor")
    public void sendHtmlEmail(String to, String subject, String htmlContent) {
        Content content = new Content("text/html", htmlContent);
        sendEmail(to, subject, content);
    }

    private void sendEmail(String to, String subject, Content content) {
        Email from = new Email(fromEmail);
        Email toEmail = new Email(to);
        Mail mail = new Mail(from, subject, toEmail, content);

        Request request = new Request();
        try {
            request.setMethod(Method.POST);
            request.setEndpoint("mail/send");
            request.setBody(mail.build());
            Response response = sendGrid.api(request);

            if (response.getStatusCode() >= 400) {
                logger.warn("Erro ao tentar enviar email: {}", response.getBody());
                throw new MailSendException("SendGrid error: " + response.getBody());
            }
        } catch (IOException e) {
            logger.warn("Erro ao tentar enviar email: {}", e.getMessage());
            throw new MailSendException("Failed to send email", e);
        }
    }
}
