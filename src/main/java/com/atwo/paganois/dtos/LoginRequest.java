package com.atwo.paganois.dtos;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record LoginRequest(
        @Schema(description = "Username", example = "userdasilva", minLength = 4,
                maxLength = 50) @NotBlank(message = "Username is required") @Size(min = 4, max = 50,
                        message = "Username deve ter entre 4 e 50 caracteres") String username,

        @Schema(description = "Senha do usuário", example = "strong@paSSworD!", format = "password",
                minLength = 6,
                maxLength = 50) @NotBlank(message = "Password is required") @Size(min = 4, max = 40,
                        message = "Senha deve ter entre 6 e 40 caracteres") String password) {
}
