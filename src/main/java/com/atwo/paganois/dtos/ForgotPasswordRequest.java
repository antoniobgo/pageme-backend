package com.atwo.paganois.dtos;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record ForgotPasswordRequest(
        @Schema(description = "Email para enviar link de reset de senha", minLength = 6,
                maxLength = 50) @NotBlank(message = "Email is required") @Email(
                        message = "Email deve ter um formáto válido") @Size(min = 6, max = 50,
                                message = "Email deve ter entre 6 e 50 caracteres") String email) {

}
