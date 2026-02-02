package com.atwo.paganois.dtos;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;

@Schema(description = "Request para logout")
public record LogoutRequest(@Schema(description = "Refresh token JWT para revogar",
        example = "eyJhbGciOiJIUzI1NiJ9...") @NotBlank(
                message = "Refresh token é obrigatório") @Pattern(
                        regexp = "^[A-Za-z0-9-_]+\\.[A-Za-z0-9-_]+\\.[A-Za-z0-9-_]+$",
                        message = "Refresh token deve estar no formato JWT válido") String refreshToken) {
}
