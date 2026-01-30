package com.atwo.paganois.entities;

import java.time.LocalDateTime;
import java.util.UUID;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;

@Entity
@Table(name = "verfication_token")
public class VerificationToken {

    @Id
    @Column(length = 36)
    private String token;

    @ManyToOne
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    @Column(nullable = false)
    private LocalDateTime expiryDate;

    @Column(length = 100)
    private String pendingEmail;

    @Enumerated(EnumType.STRING)
    private TokenType type;

    public VerificationToken() {
        token = UUID.randomUUID().toString();
    }


    public VerificationToken(User user, TokenType type, int expiryHours) {
        this();
        this.user = user;
        this.type = type;
        this.expiryDate = LocalDateTime.now().plusHours(expiryHours);
    }

    public VerificationToken(User user, TokenType type, int expiryHours, String pendingEmail) {
        this(user, type, expiryHours);
        this.pendingEmail = pendingEmail;
    }

    public boolean isExpired() {
        return LocalDateTime.now().isAfter(expiryDate);
    }

    public String getToken() {
        return token;
    }

    public void setToken(String token) {
        this.token = token;
    }

    public User getUser() {
        return user;
    }

    public void setUser(User user) {
        this.user = user;
    }

    public LocalDateTime getExpiryDate() {
        return expiryDate;
    }

    public void setExpiryDate(LocalDateTime expiryDate) {
        this.expiryDate = expiryDate;
    }

    public TokenType getType() {
        return type;
    }

    public void setType(TokenType type) {
        this.type = type;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((token == null) ? 0 : token.hashCode());
        return result;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;
        if (getClass() != obj.getClass())
            return false;
        VerificationToken other = (VerificationToken) obj;
        if (token == null) {
            if (other.token != null)
                return false;
        } else if (!token.equals(other.token))
            return false;
        return true;
    }


    public String getPendingEmail() {
        return pendingEmail;
    }


    public void setPendingEmail(String pendingEmail) {
        this.pendingEmail = pendingEmail;
    }


}
