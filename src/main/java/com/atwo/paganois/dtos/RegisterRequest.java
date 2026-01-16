package com.atwo.paganois.dtos;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public class RegisterRequest {

    @NotBlank(message = "Campo requerido")
    @Size(min = 6, max = 30)
    private String username;

    @NotBlank(message = "Campo requerido")
    @Size(min = 6, max = 25)
    private String password;

    public RegisterRequest() {
    }

    public RegisterRequest(@NotBlank(message = "Campo requerido") @Size(min = 6, max = 30) String username,
            @NotBlank(message = "Campo requerido") @Size(min = 6, max = 25) String password) {
        this.username = username;
        this.password = password;
    }

    public String getUsername() {
        return username;
    }

    public String getPassword() {
        return password;
    }

}
