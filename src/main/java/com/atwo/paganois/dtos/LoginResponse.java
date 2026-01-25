package com.atwo.paganois.dtos;

import io.swagger.v3.oas.annotations.media.Schema;

public record LoginResponse(

        @Schema(description = "Access token JWT (válido por 15 minutos)", example = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyIiwiaWF0IjoxNzA2...") String accessToken,
        @Schema(description = "Refresh token JWT (válido por 7 dias)", example = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyIiwiaWF0IjoxNzA2...") String refreshToken,
        @Schema(description = "Token type", example = "Bearer") String tokenType,
        @Schema(description = "Access token expiration time in ms") long expiresIn) {

    public LoginResponse(String accessToken, String refreshToken) {
        this(accessToken, refreshToken, "Bearer", 900000L);

    }
}