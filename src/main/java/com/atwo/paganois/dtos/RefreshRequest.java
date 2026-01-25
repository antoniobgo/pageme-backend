package com.atwo.paganois.dtos;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;

public record RefreshRequest(
    @Schema(
        description = "Refresh token JWT válido",
        example = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyIiwiaWF0IjoxNzA2..."
    )
    @NotBlank(message = "Refresh token is required")
    String refreshToken
) {}