package com.atwo.paganois.dtos;

import com.atwo.paganois.validators.StrongPassword;
import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record ResetPasswordRequest(@Schema(description = "Senha segura do usuário",
        example = "new@2paSSworD!", minLength = 8, maxLength = 40,
        format = "password") @NotBlank(message = "Senha é obrigatória") @Size(min = 8, max = 40,
                message = "Senha deve ter entre 8 e 40 caracteres") @StrongPassword String newPassword,
        @Schema(description = "Token para reset de senha",
                example = "550e8400-e29b-41d4-a716-446655440000", minLength = 36,
                maxLength = 36) @NotBlank(message = "Token é obrigatório") @Size(min = 36, max = 36,
                        message = "Token deve ter 36 caracteres") String token) {

}
