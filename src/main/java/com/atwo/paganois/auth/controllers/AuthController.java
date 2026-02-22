package com.atwo.paganois.auth.controllers;

import java.net.URI;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;
import com.atwo.paganois.auth.dtos.ForgotPasswordRequest;
import com.atwo.paganois.auth.dtos.LoginRequest;
import com.atwo.paganois.auth.dtos.LoginResponse;
import com.atwo.paganois.auth.dtos.LogoutRequest;
import com.atwo.paganois.auth.dtos.RefreshRequest;
import com.atwo.paganois.auth.dtos.RegisterRequest;
import com.atwo.paganois.auth.dtos.RegisterResponse;
import com.atwo.paganois.auth.dtos.ResendEmailVerificationRequest;
import com.atwo.paganois.auth.dtos.ResetPasswordRequest;
import com.atwo.paganois.auth.services.AuthService;
import com.atwo.paganois.shared.dtos.MessageResponse;
import com.atwo.paganois.user.entities.User;
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
    @Operation(summary = "Autenticar usuário", description = """
            Autentica o usuário e retorna access token e refresh token JWT.

            ### Tokens Retornados
            - **Access Token**: Válido por **15 minutos**. Use em todas as requisições autenticadas.
            - **Refresh Token**: Válido por **7 dias**. Use para renovar tokens expirados.

            ### Como Usar
            Aceita **username** no campo username.

            ### Pré-requisitos
            - Email deve estar verificado
            - Credenciais devem estar corretas

            ### Rate Limit
            **5 tentativas por minuto** por IP para proteção contra brute force.
            """)
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Login realizado com sucesso",
                    content = @Content(schema = @Schema(implementation = LoginResponse.class))),
            @ApiResponse(responseCode = "400",
                    description = "Dados de entrada inválidos (validação falhou)",
                    content = @Content(
                            schema = @Schema(ref = "#/components/schemas/ErrorResponse"))),
            @ApiResponse(responseCode = "401",
                    description = "Credenciais inválidas ou email não verificado",
                    content = @Content(
                            schema = @Schema(ref = "#/components/schemas/ErrorResponse"))),
            @ApiResponse(responseCode = "403", description = "Conta desabilitada",
                    content = @Content(
                            schema = @Schema(ref = "#/components/schemas/ErrorResponse"))),
            @ApiResponse(responseCode = "429",
                    description = "Rate limit excedido. Aguarde antes de tentar novamente.",
                    content = @Content(
                            schema = @Schema(ref = "#/components/schemas/ErrorResponse")))})
    @SecurityRequirements
    public ResponseEntity<LoginResponse> login(@Valid @RequestBody LoginRequest request) {
        LoginResponse response = authService.login(request);
        return ResponseEntity.ok(response);
    }

    @PostMapping("/refresh")
    @SecurityRequirements
    @Operation(summary = "Renovar access token", description = """
            Gera novos access e refresh tokens usando um refresh token válido.

            ### Quando Usar
            Use este endpoint quando o access token expirar (após 15 minutos).

            ### Resposta
            Retorna:
            - Novo **access token** (válido por 15 min)
            - Novo **refresh token** (válido por 7 dias)

            O refresh token antigo será **invalidado** após uso.

            ### Rate Limit
            40 requisições por minuto (limite geral).
            """)
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "✅ Tokens renovados com sucesso",
                    content = @Content(schema = @Schema(implementation = LoginResponse.class))),
            @ApiResponse(responseCode = "400",
                    description = "Refresh token ausente ou formato inválido",
                    content = @Content(
                            schema = @Schema(ref = "#/components/schemas/ErrorResponse"))),
            @ApiResponse(responseCode = "401", description = "Refresh token expirado ou revogado",
                    content = @Content(
                            schema = @Schema(ref = "#/components/schemas/ErrorResponse")))})
    public ResponseEntity<LoginResponse> refresh(@Valid @RequestBody RefreshRequest request) {
        LoginResponse response = authService.refresh(request);
        return ResponseEntity.ok(response);
    }

    @PostMapping("/register")
    @SecurityRequirements
    @Operation(summary = "Criar nova conta de usuário", description = """
            Cria um novo usuário no sistema e envia email de verificação automaticamente.

            ### Requisitos de Senha
            - Mínimo **8 caracteres**
            - Pelo menos **uma letra maiúscula** (A-Z)
            - Pelo menos **uma letra minúscula** (a-z)
            - Pelo menos **um número** (0-9)
            - Pelo menos **um caractere especial** (@, #, $, %, etc.)

            ### Verificação de Email
            Após o registro, um email será enviado com link de verificação.

            ### Rate Limit
            **3 registros por hora** por endereço IP para prevenir spam.
            """)
    @ApiResponses({
            @ApiResponse(responseCode = "201",
                    description = "Usuário criado com sucesso. Email de verificação enviado.",
                    content = @Content(schema = @Schema(implementation = RegisterResponse.class))),
            @ApiResponse(responseCode = "400", description = "Dados inválidos (validação falhou)",
                    content = @Content(
                            schema = @Schema(ref = "#/components/schemas/ErrorResponse"))),
            @ApiResponse(responseCode = "409", description = "Username ou email já existe",
                    content = @Content(
                            schema = @Schema(ref = "#/components/schemas/ErrorResponse"))),
            @ApiResponse(responseCode = "429",
                    description = "Rate limit excedido. Aguarde antes de tentar novamente.",
                    content = @Content(
                            schema = @Schema(ref = "#/components/schemas/ErrorResponse")))})
    public ResponseEntity<RegisterResponse> register(@Valid @RequestBody RegisterRequest request) {
        RegisterResponse response = authService.register(request);

        URI location = ServletUriComponentsBuilder.fromCurrentContextPath().path("/api/users/{id}")
                .buildAndExpand(response.id()).toUri();

        return ResponseEntity.created(location).body(response);
    }

    @PostMapping("/forgot-password")
    @SecurityRequirements
    @Operation(summary = "Solicitar reset de senha", description = """
            Envia email com link para redefinição de senha.

            ### Comportamento
            - Se o email existir, um token de reset será gerado
            - Email enviado com link válido por **1 hora**
            - Se o email não existir, retorna sucesso (segurança)

            ### Segurança
            Por motivos de segurança, sempre retorna status 202, mesmo se o
            email não estiver cadastrado. Isso previne enumeração de usuários.

            ### Rate Limit
            **3 solicitações por hora** por IP.
            """)
    @ApiResponses({
            @ApiResponse(responseCode = "202",
                    description = "Se o email existir, instruções foram enviadas",
                    content = @Content(schema = @Schema(implementation = MessageResponse.class))),
            @ApiResponse(responseCode = "400", description = "Email inválido ou ausente",
                    content = @Content(
                            schema = @Schema(ref = "#/components/schemas/ErrorResponse"))),
            @ApiResponse(responseCode = "429",
                    description = "Rate limit excedido. Aguarde antes de tentar novamente.",
                    content = @Content(
                            schema = @Schema(ref = "#/components/schemas/ErrorResponse")))})
    public ResponseEntity<MessageResponse> forgotPassword(
            @Valid @RequestBody ForgotPasswordRequest request) {

        authService.sendPasswordResetEmail(request.email());

        MessageResponse response = new MessageResponse(
                "Se o email existir em nosso sistema, você receberá instruções para redefinir sua senha.");

        return ResponseEntity.status(HttpStatus.ACCEPTED).body(response);
    }

    @PostMapping("/resend-verification")
    @SecurityRequirements
    @Operation(summary = "Reenviar email de verificação", description = """
            Reenvia o email de verificação para usuários não verificados.

            ### Quando Usar
            - Email de verificação não chegou
            - Token de verificação expirou (24h)
            - Email foi perdido ou deletado

            ### Comportamento
            - Gera novo token de verificação
            - Invalida token anterior
            - Envia novo email com link atualizado
            - Por segurança, sempre retorna sucesso

            ### Pré-requisito
            Usuário deve estar registrado mas **não verificado**.

            ### Rate Limit
            **3 solicitações por hora** por IP para prevenir spam.
            """)
    @ApiResponses({@ApiResponse(responseCode = "202",
            description = "✅ Se o email existir e não estiver verificado, novo link será enviado",
            content = @Content(schema = @Schema(implementation = MessageResponse.class))),
            @ApiResponse(responseCode = "400",
                    description = "Email com formato inválido ou não fornecido",
                    content = @Content(
                            schema = @Schema(ref = "#/components/schemas/ErrorResponse"))),
            @ApiResponse(responseCode = "429",
                    description = "Rate limit excedido. Aguarde antes de tentar novamente.",
                    content = @Content(
                            schema = @Schema(ref = "#/components/schemas/ErrorResponse")))})
    public ResponseEntity<MessageResponse> resendVerification(
            @Valid @RequestBody ResendEmailVerificationRequest request) {

        authService.resendEmailVerification(request.email());

        MessageResponse response = new MessageResponse(
                "Se o email existir e não estiver verificado, você receberá um novo link de verificação.");

        return ResponseEntity.status(HttpStatus.ACCEPTED).body(response);
    }

    @PatchMapping("/reset-password")
    @SecurityRequirements
    @Operation(summary = "Redefinir senha com token", description = """
            Redefine a senha do usuário usando o token recebido por email.

            ### Token
            - Obtido via email enviado em `/auth/forgot-password`
            - Válido por **1 hora**
            - **Uso único** - token é invalidado após uso

            ### Requisitos de Nova Senha
            Mesmos requisitos de registro (validado via @StrongPassword):
            - Mínimo 8 caracteres
            - Letra maiúscula, minúscula, número e caractere especial

            ### Rate Limit
            40 requisições por minuto (limite geral).
            """)
    @ApiResponses({@ApiResponse(responseCode = "204", description = "Senha redefinida com sucesso"),
            @ApiResponse(responseCode = "400",
                    description = "Token inválido ou senha não atende requisitos",
                    content = @Content(
                            schema = @Schema(ref = "#/components/schemas/ErrorResponse"))),
            @ApiResponse(responseCode = "404", description = "Token não encontrado",
                    content = @Content(
                            schema = @Schema(ref = "#/components/schemas/ErrorResponse"))),
            @ApiResponse(responseCode = "410", description = "Token expirado", content = @Content(
                    schema = @Schema(ref = "#/components/schemas/ErrorResponse")))})
    public ResponseEntity<Void> resetPassword(@Valid @RequestBody ResetPasswordRequest request) {

        authService.resetPassword(request.token(), request.newPassword());

        return ResponseEntity.noContent().build();
    }

    @GetMapping("/verify-email")
    @SecurityRequirements
    @Operation(summary = "Verificar email do usuário", description = """
            Confirma o email do usuário através do token enviado por email.

            ### Processo
            1. Usuário clica no link recebido no email de registro
            2. Token é validado
            3. Email é marcado como verificado
            4. Usuário pode fazer login

            ### Token
            - Válido por **24 horas**
            - **Uso único** - invalidado após verificação

            ### Após Verificação
            O usuário poderá fazer login normalmente.

            ### Rate Limit
            40 requisições por minuto (limite geral).
            """)
    @ApiResponses({
            @ApiResponse(responseCode = "200",
                    description = "Email verificado com sucesso. Agora você pode fazer login!",
                    content = @Content(schema = @Schema(implementation = MessageResponse.class))),
            @ApiResponse(responseCode = "400", description = "Tipo de token inválido",
                    content = @Content(
                            schema = @Schema(ref = "#/components/schemas/ErrorResponse"))),
            @ApiResponse(responseCode = "404", description = "Token não encontrado no sistema",
                    content = @Content(
                            schema = @Schema(ref = "#/components/schemas/ErrorResponse"))),
            @ApiResponse(responseCode = "410", description = "Token expirado", content = @Content(
                    schema = @Schema(ref = "#/components/schemas/ErrorResponse")))})
    public ResponseEntity<MessageResponse> verifyEmail(@RequestParam @NotBlank @Size(min = 36,
            max = 36, message = "Token deve ter 36 caracteres") String token) {

        authService.verifyEmail(token);
        return ResponseEntity.ok(new MessageResponse("Email verificado com sucesso!"));
    }

    @PostMapping("/logout")
    @SecurityRequirement(name = "bearerAuth")
    @Operation(summary = "Fazer logout", description = """
            Invalida o refresh token do usuário, efetivando o logout deste dispositivo.

            ### Comportamento
            - O refresh token fornecido será **revogado**
            - O access token continuará válido até expirar naturalmente (15 min)
            - Para segurança máxima, remova ambos tokens do client-side

            ### Autenticação Necessária
            Requer access token válido no header Authorization.

            ### Rate Limit
            40 requisições por minuto (limite geral).
            """)
    @ApiResponses({@ApiResponse(responseCode = "204", description = "Logout realizado com sucesso"),
            @ApiResponse(responseCode = "400", description = "Refresh token inválido",
                    content = @Content(
                            schema = @Schema(ref = "#/components/schemas/ErrorResponse"))),
            @ApiResponse(responseCode = "401", description = "Access token inválido ou ausente",
                    content = @Content(
                            schema = @Schema(ref = "#/components/schemas/ErrorResponse")))})
    @PreAuthorize("hasAnyRole('ROLE_USER', 'ROLE_ADMIN')")
    public ResponseEntity<Void> logout(@Valid @RequestBody LogoutRequest request,
            HttpServletRequest httpRequest) {

        String authHeader = httpRequest.getHeader("Authorization");
        String accessToken = authHeader.substring(7);

        authService.logout(accessToken, request.refreshToken());

        return ResponseEntity.noContent().build();
    }

    @PostMapping("/logout-all")
    @SecurityRequirement(name = "bearerAuth")
    @Operation(summary = "Fazer logout de todos os dispositivos", description = """
            Revoga **TODOS** os tokens do usuário simultaneamente.

            ### Comportamento
            - Invalida todos os refresh tokens do usuário
            - Access tokens existentes continuam válidos até expirarem
            - Usuário será deslogado de **todos os dispositivos**
            - Útil em caso de segurança comprometida

            ### Caso de Uso
            Use quando:
            - Suspeitar que sua conta foi acessada indevidamente
            - Quiser deslogar de todos os dispositivos remotamente
            - Perdeu acesso a algum dispositivo

            ### Autenticação Necessária
            Requer access token válido.

            ### Rate Limit
            40 requisições por minuto (limite geral).
            """)
    @ApiResponses({
            @ApiResponse(responseCode = "204",
                    description = "Logout global realizado. Todos os tokens foram revogados."),
            @ApiResponse(responseCode = "401", description = "Access token inválido ou ausente",
                    content = @Content(
                            schema = @Schema(ref = "#/components/schemas/ErrorResponse")))})
    @PreAuthorize("hasAnyRole('ROLE_USER', 'ROLE_ADMIN')")
    public ResponseEntity<Void> logoutAllDevices(@AuthenticationPrincipal User user) {
        authService.logoutAllDevices(user.getUsername());
        return ResponseEntity.noContent().build();
    }

}
