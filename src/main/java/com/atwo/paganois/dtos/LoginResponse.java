package com.atwo.paganois.dtos;

public record LoginResponse(
        String accessToken,
        String refreshToken,
        String tokenType,
        long expiresIn) {

    public LoginResponse(String accessToken, String refreshToken) {
        this(accessToken, refreshToken, "Bearer", 900000L);

    }
}