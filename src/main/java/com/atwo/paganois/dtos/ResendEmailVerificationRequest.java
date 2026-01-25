package com.atwo.paganois.dtos;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;

public record ResendEmailVerificationRequest(
                @Schema(description = "Email para reenviar link de verificação de email") @NotBlank(message = "Email is required") String email) {

}
