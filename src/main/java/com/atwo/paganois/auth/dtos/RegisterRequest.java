package com.atwo.paganois.auth.dtos;

import com.atwo.paganois.shared.validators.StrongPassword;
import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

@Schema(description = "Request para registro de novo usuário")
public class RegisterRequest {

    @Schema(description = "Nome de usuário único no sistema (apenas letras, números e underscore)",
            example = "joaosilva", requiredMode = Schema.RequiredMode.REQUIRED, minLength = 6,
            maxLength = 50, pattern = "^[a-zA-Z0-9_]+$")
    @NotBlank(message = "Username é obrigatório")
    @Size(min = 6, max = 50, message = "Username deve ter entre 6 e 50 caracteres")
    private String username;

    @Schema(description = "Endereço de email válido e único", example = "joao.silva@example.com",
            requiredMode = Schema.RequiredMode.REQUIRED, format = "email", minLength = 6,
            maxLength = 50)
    @NotBlank(message = "Email é obrigatório")
    @Size(min = 6, max = 50, message = "Email deve ter entre 6 e 50 caracteres")
    @Email
    private String email;

    @Schema(description = """
            Senha segura que deve conter:
            - Mínimo 8 caracteres
            - Pelo menos 1 letra maiúscula
            - Pelo menos 1 letra minúscula
            - Pelo menos 1 número
            - Pelo menos 1 caractere especial (@#$%^&+=!)
            """, example = "S3nh@Fort3!", requiredMode = Schema.RequiredMode.REQUIRED,
            format = "password", minLength = 8, maxLength = 40)
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
