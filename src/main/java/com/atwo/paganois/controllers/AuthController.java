package com.atwo.paganois.controllers;

import java.net.URI;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
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
import com.atwo.paganois.dtos.LogoutRequest;
import com.atwo.paganois.dtos.MessageResponse;
import com.atwo.paganois.dtos.RefreshRequest;
import com.atwo.paganois.dtos.RegisterRequest;
import com.atwo.paganois.dtos.RegisterResponse;
import com.atwo.paganois.dtos.ResendEmailVerificationRequest;
import com.atwo.paganois.dtos.ResetPasswordRequest;
import com.atwo.paganois.entities.User;
import com.atwo.paganois.services.AuthService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.security.SecurityRequirements;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

@RestController
@RequestMapping("/auth")
@Tag(name = "Autenticação", description = "Endpoints de autenticação")
public class AuthController {

    @Autowired
    private AuthService authService;

    @PostMapping("/login")
    @Operation(summary = "Fazer login",
            description = "Autentica usuário e retorna access token e refresh token JWT")
    @ApiResponses(
            value = {
                    @ApiResponse(responseCode = "200", description = "Login realizado com sucesso",
                            content = @Content(
                                    schema = @Schema(implementation = LoginResponse.class))),
                    @ApiResponse(responseCode = "400",
                            description = "Dados de login inválidos (validação)"),
                    @ApiResponse(responseCode = "401", description = "Credenciais inválidas"),
                    @ApiResponse(responseCode = "403",
                            description = "Conta desabilitada ou não verificada")})
    @SecurityRequirements
    public ResponseEntity<LoginResponse> login(@Valid @RequestBody LoginRequest request) {
        LoginResponse response = authService.login(request);
        return ResponseEntity.ok(response);
    }

    @PostMapping("/refresh")
    @Operation(summary = "Renovar access token",
            description = "Gera novo access token usando refresh token válido")
    @ApiResponses(
            value = {
                    @ApiResponse(responseCode = "200", description = "Token renovado com sucesso",
                            content = @Content(
                                    schema = @Schema(implementation = LoginResponse.class))),
                    @ApiResponse(
                            responseCode = "400",
                            description = "Formato do refresh token inválido"),
                    @ApiResponse(responseCode = "401",
                            description = "Refresh token inválido ou expirado")})
    @SecurityRequirements
    public ResponseEntity<LoginResponse> refresh(@Valid @RequestBody RefreshRequest request) {
        LoginResponse response = authService.refresh(request);
        return ResponseEntity.ok(response);
    }

    @PostMapping("/register")
    @Operation(summary = "Registrar novo usuário",
            description = "Cria uma nova conta de usuário e envia email de confirmação. "
                    + "O usuário precisa verificar o email antes de fazer login.")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "201",
                    description = "Usuário criado com sucesso. Email de verificação enviado.",
                    content = @Content(schema = @Schema(implementation = RegisterResponse.class))),
            @ApiResponse(responseCode = "400", description = "Dados de registro inválidos"),
            @ApiResponse(responseCode = "409", description = "Username ou email já existe")})
    @SecurityRequirements
    public ResponseEntity<RegisterResponse> register(@Valid @RequestBody RegisterRequest request) {
        RegisterResponse response = authService.register(request);

        URI location = ServletUriComponentsBuilder.fromCurrentContextPath().path("/api/users/{id}")
                .buildAndExpand(response.id()).toUri();

        return ResponseEntity.created(location).body(response);
    }

    @PostMapping("/forgot-password")
    @Operation(summary = "Solicitar reset de senha",
            description = "Envia email com link para redefinir senha. "
                    + "Por segurança, sempre retorna sucesso mesmo se o email em formáto válido não existir.")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "202",
                    description = "Solicitação aceita. Se o email existir, um link será enviado."),
            @ApiResponse(responseCode = "400",
                    description = "Email com formato inválido ou não fornecido")})
    @SecurityRequirements
    public ResponseEntity<MessageResponse> forgotPassword(
            @Valid @RequestBody ForgotPasswordRequest request) {

        authService.sendPasswordResetEmail(request.email());

        MessageResponse response = new MessageResponse(
                "Se o email existir em nosso sistema, você receberá instruções para redefinir sua senha.");

        return ResponseEntity.status(HttpStatus.ACCEPTED).body(response);
    }

    @PostMapping("/resend-verification")
    @Operation(summary = "Reenviar email de verificação",
            description = "Reenvia o email de confirmação de conta. "
                    + "Por segurança, sempre retorna sucesso.")
    @ApiResponses(value = {@ApiResponse(responseCode = "202",
            description = "Solicitação aceita. Se o email existir e não estiver verificado, um novo link será enviado."),
            @ApiResponse(responseCode = "400",
                    description = "Email com formato inválido ou não fornecido")})
    @SecurityRequirements
    public ResponseEntity<MessageResponse> resendVerification(
            @Valid @RequestBody ResendEmailVerificationRequest request) {

        authService.resendEmailVerification(request.email());

        MessageResponse response = new MessageResponse(
                "Se o email existir e não estiver verificado, você receberá um novo link de verificação.");

        return ResponseEntity.status(HttpStatus.ACCEPTED).body(response);
    }

    @PostMapping("/reset-password")
    @Operation(summary = "Resetar senha",
            description = "Define nova senha usando token de reset recebido por email")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "204", description = "Senha redefinida com sucesso"),
            @ApiResponse(responseCode = "400",
                    description = "Senha não atende aos requisitos mínimos ou tipo de token inválido"),
            @ApiResponse(responseCode = "404", description = "Token não encontrado"),
            @ApiResponse(responseCode = "410", description = "Token expirado")})
    @SecurityRequirements
    public ResponseEntity<Void> resetPassword(@Valid @RequestBody ResetPasswordRequest request) {

        authService.resetPassword(request.token(), request.newPassword());

        return ResponseEntity.noContent().build();
    }

    @GetMapping("/verify-email")
    @Operation(summary = "Verificar email",
            description = "Confirma email do usuário através do token enviado por email. "
                    + "Retorna página HTML para melhor experiência do usuário.")
    @ApiResponses(
            value = {
                    @ApiResponse(responseCode = "200", description = "Email verificado com sucesso",
                            content = @Content(
                                    schema = @Schema(implementation = MessageResponse.class))),
                    @ApiResponse(responseCode = "400", description = "Tipo de token inválido"),
                    @ApiResponse(responseCode = "404", description = "Token não encontrado"),
                    @ApiResponse(responseCode = "410", description = "Token expirado")})
    @SecurityRequirements
    public ResponseEntity<MessageResponse> verifyEmail(@RequestParam @NotBlank @Size(min = 36,
            max = 36, message = "Token deve ter 36 caracteres") String token) {

        authService.verifyEmail(token);
        return ResponseEntity.ok(new MessageResponse("Email verificado com sucesso!"));
    }

    @PostMapping("/logout")
    @Operation(summary = "Fazer logout",
            description = "Revoga o access token e refresh token atual. "
                    + "O usuário precisará fazer login novamente neste dispositivo.")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "204", description = "Logout realizado com sucesso"),
            @ApiResponse(responseCode = "400", description = "Refresh token inválido"),
            @ApiResponse(responseCode = "401", description = "Não autenticado")})
    @SecurityRequirement(name = "bearerAuth")
    @PreAuthorize("hasAnyRole('ROLE_USER', 'ROLE_ADMIN')")
    public ResponseEntity<Void> logout(@Valid @RequestBody LogoutRequest request,
            HttpServletRequest httpRequest) {

        String authHeader = httpRequest.getHeader("Authorization");
        String accessToken = authHeader.substring(7);

        authService.logout(accessToken, request.refreshToken());

        return ResponseEntity.noContent().build();
    }

    @PostMapping("/logout-all")
    @Operation(summary = "Fazer logout de todos os dispositivos",
            description = "Revoga TODOS os tokens do usuário. "
                    + "O usuário será deslogado de todos os dispositivos e precisará fazer login novamente.")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "204", description = "Logout global realizado com sucesso"),
            @ApiResponse(responseCode = "401", description = "Não autenticado")})
    @SecurityRequirement(name = "bearerAuth")
    @PreAuthorize("hasAnyRole('ROLE_USER', 'ROLE_ADMIN')")
    public ResponseEntity<Void> logoutAllDevices(@AuthenticationPrincipal User user) {
        authService.logoutAllDevices(user.getUsername());
        return ResponseEntity.noContent().build();
    }

}
