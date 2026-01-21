package com.atwo.paganois.dtos;

import jakarta.validation.constraints.NotBlank;

public record ForgotPasswordRequest(
    @NotBlank(message = "Email is required") String email
) {

}
