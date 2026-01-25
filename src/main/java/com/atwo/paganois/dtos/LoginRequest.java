package com.atwo.paganois.dtos;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;

public record LoginRequest(
                @Schema(description = "Username ou email", example = "userdasilva") @NotBlank(message = "Username is required") String username,

                @NotBlank(message = "Password is required") @Schema(description = "Senha do usuário", example = "strong@paSSworD!", format = "password") String password) {
}