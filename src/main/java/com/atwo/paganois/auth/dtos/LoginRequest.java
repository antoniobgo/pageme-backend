package com.atwo.paganois.auth.dtos;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

@Schema(description = "Credenciais para autenticação do usuário")
public record LoginRequest(

        @Schema(description = "Nome de usuário", example = "user",
                requiredMode = Schema.RequiredMode.REQUIRED,
                maxLength = 50) @NotBlank(message = "Username é obrigatório") @Size(max = 50,
                        message = "Username deve ter no máximo 50 caracteres") String username,

        @Schema(description = "Senha do usuário", example = "password",
                requiredMode = Schema.RequiredMode.REQUIRED, format = "password",
                maxLength = 40) @NotBlank(message = "Password é obrigatório") @Size(max = 40,
                        message = "Senha deve ter no máximo 40 caracteres") String password

) {
}
