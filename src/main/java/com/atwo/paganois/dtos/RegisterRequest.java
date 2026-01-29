package com.atwo.paganois.dtos;

import com.atwo.paganois.validators.StrongPassword;
import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

@Schema(description = "Request para registro de novo usuário")
public class RegisterRequest {

    @Schema(description = "Nome de usuário único", example = "userdasilva", minLength = 6,
            maxLength = 50)
    @NotBlank(message = "Username é obrigatório")
    @Size(min = 6, max = 50, message = "Username deve ter entre 6 e 50 caracteres")
    private String username;

    @Schema(description = "Email do usuário", example = "joao@example.com", format = "email",
            minLength = 6, maxLength = 50)
    @NotBlank(message = "Email é obrigatório")
    @Size(min = 6, max = 50, message = "Email deve ter entre 6 e 50 caracteres")
    @Email
    private String email;

    @Schema(description = "Senha do usuário", example = "strong@paSSworD!", minLength = 8,
            maxLength = 40, format = "password")
    @NotBlank(message = "Senha é obrigatória")
    @Size(min = 6, max = 40, message = "Senha deve ter entre 8 e 40 caracteres")
    @StrongPassword
    private String password;

    public RegisterRequest() {}

    public RegisterRequest(String username, String password, String email) {
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
