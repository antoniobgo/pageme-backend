package com.atwo.paganois.dtos;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;

public record ResetPasswordRequest(
                @Schema(description = "Nova senha para o usuário") @NotBlank(message = "New password is required") String newPassword) {

}
