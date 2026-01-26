package com.atwo.paganois.dtos;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;

public record ForgotPasswordRequest(
        @Schema(description = "Email para enviar link de reset de senha") @NotBlank(
                message = "Email is required") @Email(
                        message = "Email deve ter um formáto válido") String email) {

}
