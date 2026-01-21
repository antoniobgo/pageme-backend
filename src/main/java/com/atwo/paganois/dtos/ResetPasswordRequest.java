package com.atwo.paganois.dtos;

import jakarta.validation.constraints.NotBlank;

public record ResetPasswordRequest(
        @NotBlank(message = "New password is required") String newPassword) {

}
