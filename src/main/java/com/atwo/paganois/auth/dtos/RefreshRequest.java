package com.atwo.paganois.auth.dtos;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;

public record RefreshRequest(@Schema(description = "Refresh token JWT válido",
        example = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyIiwiaWF0IjoxNzA2.dQw4w9WgXcQ") @NotBlank(
                message = "Refresh token é obrigatório") @Pattern(
                        regexp = "^[A-Za-z0-9-_]+\\.[A-Za-z0-9-_]+\\.[A-Za-z0-9-_]+$",
                        message = "Refresh token deve estar no formato JWT válido") String refreshToken) {
}
