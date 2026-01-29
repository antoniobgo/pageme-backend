package com.atwo.paganois.dtos;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record UpdateEmailRequest(
        @Schema(description = "Novo email", example = "usuario@example.com", minLength = 6,
                maxLength = 50) @NotBlank(message = "Email é obrigatório") @Email(
                        message = "Email deve ter um formato válido") @Size(min = 6, max = 50,
                                message = "Email deve ter entre 6 e 50 caracteres") String email) {

}
