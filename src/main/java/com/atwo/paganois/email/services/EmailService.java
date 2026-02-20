package com.atwo.paganois.email.services;

import jakarta.mail.MessagingException;

public interface EmailService {
    void sendSimpleEmail(String to, String subject, String text);

    void sendHtmlEmail(String to, String subject, String html) throws MessagingException;
}
