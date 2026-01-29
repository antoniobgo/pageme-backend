package com.atwo.paganois.dtos;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record LoginRequest(
        @Schema(description = "Username", example = "user", maxLength = 50) @NotBlank(
                message = "Username é obrigatório") @Size(max = 50,
                        message = "Username deve ter no máximo 50 caracteres") String username,

        @Schema(description = "Senha forte: mín. 8 chars, 1 maiúscula, 1 minúscula, 1 número, 1 especial (@$!%*?&#)",
                example = "strong2paSSworD!", format = "password",
                maxLength = 50) @NotBlank(message = "Password é obrigatório") @Size(max = 40,
                        message = "Senha deve ter no máximo 40 caracteres") String password) {
}
