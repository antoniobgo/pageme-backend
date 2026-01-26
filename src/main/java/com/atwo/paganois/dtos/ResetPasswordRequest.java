package com.atwo.paganois.dtos;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record ResetPasswordRequest(
        @Schema(description = "Senha do usuário", example = "new@paSSworD!", minLength = 6, maxLength = 50, format = "password") @NotBlank(message = "Senha é obrigatória") @Size(min = 6, max = 40, message = "Senha deve ter entre 6 e 40 caracteres") String newPassword) {

}
