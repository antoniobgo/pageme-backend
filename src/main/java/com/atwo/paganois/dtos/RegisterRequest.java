package com.atwo.paganois.dtos;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public class RegisterRequest {

    @NotBlank(message = "Campo requerido")
    @Size(min = 6, max = 30)
    private String username;

    @NotBlank(message = "Campo requerido")
    @Size(min = 6, max = 50)
    @Email
    private String email;

    @NotBlank(message = "Campo requerido")
    @Size(min = 6, max = 25)
    private String password;

    public RegisterRequest() {
    }

    public RegisterRequest(String username,
            String password, String email) {
        this.username = username;
        this.password = password;
        this.email = email;
    }

    public String getUsername() {
        return username;
    }

    public String getPassword() {
        return password;
    }

    public String getEmail() {
        return email;
    }

}
