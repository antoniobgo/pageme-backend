
package com.atwo.paganois.dtos;

import com.atwo.paganois.validators.StrongPassword;
import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record UpdatePasswordRequest(@Schema(description = "Nova senha segura do usuário",
        example = "new@2paSSworD!", minLength = 8, maxLength = 40,
        format = "password") @NotBlank(message = "Nova senha é obrigatória") @Size(min = 8,
                max = 40,
                message = "Senha deve ter entre 8 e 40 caracteres") @StrongPassword String newPassword,

        @Schema(description = "Senha antiga do usuário", example = "strong2paSSworD!",
                maxLength = 40,
                format = "password") @NotBlank(message = "Antiga senha é obrigatória") @Size(
                        max = 40,
                        message = "Senha deve ter no máximo 40 caracteres") String oldPassword) {
}


// import com.fasterxml.jackson.annotation.JsonProperty;

// public record UpdatePasswordRequest(@JsonProperty("newPassword") String newPassword,
// @JsonProperty("oldPassword") String oldPassword) {
// }
