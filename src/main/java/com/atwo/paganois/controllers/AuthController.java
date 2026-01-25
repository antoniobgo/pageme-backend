package com.atwo.paganois.controllers;

import java.net.URI;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

import com.atwo.paganois.dtos.ForgotPasswordRequest;
import com.atwo.paganois.dtos.LoginRequest;
import com.atwo.paganois.dtos.LoginResponse;
import com.atwo.paganois.dtos.RefreshRequest;
import com.atwo.paganois.dtos.RegisterRequest;
import com.atwo.paganois.dtos.RegisterResponse;
import com.atwo.paganois.dtos.ResendEmailVerificationRequest;
import com.atwo.paganois.dtos.ResetPasswordRequest;
import com.atwo.paganois.services.AuthService;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirements;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;

@RestController
@RequestMapping("/auth")
@Tag(name = "Autenticação", description = "Endpoints de autenticação e gerenciamento de usuários")
public class AuthController {

    @Autowired
    private AuthService authService;

    @PostMapping("/login")
    @Operation(summary = "Fazer login", description = "Autentica usuário e retorna access token e refresh token JWT")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Login realizado com sucesso", content = @Content(schema = @Schema(implementation = LoginResponse.class))),
            @ApiResponse(responseCode = "401", description = "Credenciais inválidas")
    })
    @SecurityRequirements
    public ResponseEntity<LoginResponse> login(@Valid @RequestBody LoginRequest request) {
        return ResponseEntity.ok(authService.login(request));
    }

    @PostMapping("/refresh")
    @Operation(summary = "Renovar access token", description = "Gera novo access token usando refresh token válido")
    @SecurityRequirements
    public ResponseEntity<LoginResponse> refresh(@Valid @RequestBody RefreshRequest request) {
        return ResponseEntity.ok(authService.refresh(request));
    }

    @PostMapping("/register")
    @Operation(summary = "Registrar novo usuário", description = "Cria uma nova conta de usuário e envia email de confirmação")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "201", description = "Usuário criado com sucesso", content = @Content(schema = @Schema(implementation = RegisterResponse.class))),
            @ApiResponse(responseCode = "409", description = "Username ou email já existe")
    })
    @SecurityRequirements
    public ResponseEntity<RegisterResponse> register(@Valid @RequestBody RegisterRequest request) {

        RegisterResponse response = authService.register(request);

        URI location = ServletUriComponentsBuilder
                .fromCurrentContextPath()
                .path("/api/users/{id}")
                .buildAndExpand(response.id())
                .toUri();
        return ResponseEntity.created(location).body(response);
    }

    @PostMapping("/forgot-password")
    @Operation(
        summary = "Solicitar reset de senha",
        description = "Envia email com link para redefinir senha"
    )
    @SecurityRequirements
    public ResponseEntity<Void> forgotPassword(@RequestBody ForgotPasswordRequest request) {
        authService.sendPasswordResetEmail(request.email());
        return ResponseEntity.ok(null);
    }

    @PostMapping("/resend-verification")
    public ResponseEntity<Void> resendVerification(@RequestBody ResendEmailVerificationRequest request) {
        authService.resendEmailVerification(request.email());
        return ResponseEntity.ok(null);
    }

    @PostMapping("/reset-password")
    @Operation(
        summary = "Resetar senha",
        description = "Define nova senha usando token de reset"
    )
    @SecurityRequirements
    public ResponseEntity<Void> resetPassword(@RequestParam String token, @RequestBody ResetPasswordRequest request) {
        authService.resetPassword(token, request.newPassword());
        return ResponseEntity.ok(null);
    }

    // TODO: resposta html generico, usar frontend ou adaptar
    @GetMapping("/verify-email")
    @Operation(summary = "Verificar email", description = "Confirma email do usuário através do token enviado por email")
    @SecurityRequirements
    public ResponseEntity<String> verifyEmail(@RequestParam String token) {

        authService.verifyEmail(token);

        String html = """
                <!DOCTYPE html>
                <html lang="pt-BR">
                <head>
                    <meta charset="UTF-8">
                    <meta name="viewport" content="width=device-width, initial-scale=1.0">
                    <title>Email Verificado</title>
                    <style>
                        body {
                            font-family: Arial, sans-serif;
                            display: flex;
                            justify-content: center;
                            align-items: center;
                            min-height: 100vh;
                            margin: 0;
                            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                        }
                        .card {
                            background: white;
                            padding: 40px;
                            border-radius: 10px;
                            box-shadow: 0 10px 40px rgba(0,0,0,0.2);
                            text-align: center;
                            max-width: 400px;
                        }
                        .success-icon {
                            font-size: 64px;
                            color: #4CAF50;
                            margin-bottom: 20px;
                        }
                        h1 {
                            color: #333;
                            margin-bottom: 10px;
                        }
                        p {
                            color: #666;
                            margin-bottom: 30px;
                        }
                        .button {
                            display: inline-block;
                            padding: 12px 30px;
                            background: #667eea;
                            color: white;
                            text-decoration: none;
                            border-radius: 5px;
                            transition: background 0.3s;
                        }
                        .button:hover {
                            background: #5568d3;
                        }
                    </style>
                </head>
                <body>
                    <div class="card">
                        <div class="success-icon">✅</div>
                        <h1>Email Verificado!</h1>
                        <p>Sua conta foi ativada com sucesso. Você já pode fazer login.</p>
                        <a href="/login" class="button">Ir para Login</a>
                    </div>
                </body>
                </html>
                """;

        return ResponseEntity.ok().contentType(org.springframework.http.MediaType.TEXT_HTML).body(html);
    }

}
