package com.atwo.paganois.user.controllers;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import com.atwo.paganois.auth.dtos.ChangeEmailRequest;
import com.atwo.paganois.shared.dtos.MessageResponse;
import com.atwo.paganois.user.dtos.UpdatePasswordRequest;
import com.atwo.paganois.user.dtos.UserDTO;
import com.atwo.paganois.user.entities.User;
import com.atwo.paganois.user.services.UserService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

@RestController
@RequestMapping(path = "/api/users")
@SecurityRequirement(name = "bearerAuth")
@Tag(name = "Users", description = "Endpoints de gerenciamento de usuários")
public class UserController {

    @Autowired
    private UserService userService;

    @GetMapping(path = "/me")
    @Operation(summary = "Obter perfil do usuário autenticado", description = """
            Retorna informações completas do perfil do usuário logado.

            ### Informações Retornadas
            - ID do usuário
            - Username
            - Email
            - Role (permissões)
            - Status da conta (ativa/inativa)
            - Status de verificação de email

            ### Autenticação Necessária
            Requer access token válido no header Authorization.

            ### Uso Comum
            - Carregar dados do perfil ao iniciar aplicação
            - Verificar status de verificação de email
            - Exibir informações do usuário na interface

            ### Rate Limit
            100 requisições por minuto (limite geral).
            """)
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Perfil retornado com sucesso",
                    content = @Content(schema = @Schema(implementation = UserDTO.class))),
            @ApiResponse(responseCode = "401", description = "Token inválido, ausente ou expirado",
                    content = @Content(
                            schema = @Schema(ref = "#/components/schemas/ErrorResponse"))),
            @ApiResponse(responseCode = "403", description = "Conta desabilitada",
                    content = @Content(
                            schema = @Schema(ref = "#/components/schemas/ErrorResponse")))})
    @PreAuthorize("hasAnyRole('ROLE_USER', 'ROLE_ADMIN')")
    public ResponseEntity<UserDTO> getMe(@AuthenticationPrincipal User user) {
        UserDTO userResponse = userService.getAuthenticatedUserProfile(user);
        return ResponseEntity.ok(userResponse);
    }

    @PatchMapping(path = "/me/password")
    @Operation(summary = "Alterar senha do usuário autenticado", description = """
            Permite que o usuário altere sua própria senha.

            ### Requisitos
            - Fornecer senha **atual** correta
            - Nova senha deve atender aos requisitos de segurança

            ### Nova Senha Deve Conter
            - Mínimo 8 caracteres
            - Letra maiúscula, minúscula, número e caractere especial

            ### Autenticação Necessária
            Requer access token válido.

            ### Rate Limit
            100 requisições por minuto (limite geral).
            """)
    @ApiResponses({@ApiResponse(responseCode = "204", description = "Senha alterada com sucesso"),
            @ApiResponse(responseCode = "400", description = "Nova senha não atende aos requisitos",
                    content = @Content(
                            schema = @Schema(ref = "#/components/schemas/ErrorResponse"))),
            @ApiResponse(responseCode = "401", description = "Token inválido ou ausente",
                    content = @Content(
                            schema = @Schema(ref = "#/components/schemas/ErrorResponse"))),
            @ApiResponse(responseCode = "403", description = "Senha atual incorreta",
                    content = @Content(
                            schema = @Schema(ref = "#/components/schemas/ErrorResponse")))})
    @PreAuthorize("hasAnyRole('ROLE_USER', 'ROLE_ADMIN')")
    public ResponseEntity<Void> updatePassword(@AuthenticationPrincipal User user,
            @RequestBody UpdatePasswordRequest request) {
        userService.updatePassword(user, request.newPassword(), request.oldPassword());
        return ResponseEntity.noContent().build();
    }

    @PatchMapping(path = "/me/email")
    @Operation(summary = "Solicitar mudança de email", description = """
            Inicia processo de mudança de email do usuário autenticado.

            ### Processo em 2 Etapas
            1. **Solicitação**: Este endpoint envia email de confirmação
            2. **Confirmação**: Usuário clica no link recebido por email

            ### Comportamento
            - Token de confirmação gerado (válido 1 hora)
            - Email enviado ao **novo endereço** com link de confirmação
            - Email só é alterado após confirmação

            ### Validações
            - Novo email deve ser válido
            - Novo email não pode estar em uso

            ### Autenticação Necessária
            Requer access token válido.

            ### Rate Limit
            100 requisições por minuto (limite geral).
            """)
    @ApiResponses({
            @ApiResponse(responseCode = "200",
                    description = "✅ Email de confirmação enviado para o novo endereço",
                    content = @Content(schema = @Schema(implementation = MessageResponse.class))),
            @ApiResponse(responseCode = "400", description = "Novo email inválido ou já em uso",
                    content = @Content(
                            schema = @Schema(ref = "#/components/schemas/ErrorResponse"))),
            @ApiResponse(responseCode = "401", description = "Token inválido ou ausente",
                    content = @Content(
                            schema = @Schema(ref = "#/components/schemas/ErrorResponse")))})
    @PreAuthorize("hasAnyRole('ROLE_USER', 'ROLE_ADMIN')")
    public ResponseEntity<MessageResponse> requestEmailChange(@AuthenticationPrincipal User user,
            @Valid @RequestBody ChangeEmailRequest request) {

        userService.requestEmailChange(user, request.newEmail());

        return ResponseEntity.ok().body(
                new MessageResponse("Email de confirmação enviado para " + request.newEmail()));
    }

    @GetMapping(path = "/me/email/confirm")
    @Operation(summary = "Confirmar mudança de email", description = """
            Confirma e efetiva a mudança de email usando token recebido.

            ### Resultado
            - Email do usuário é atualizado
            - Token é invalidado (uso único)
            - Usuário recebe confirmação

            ### Token
            - Obtido via email enviado em `/api/users/me/email`
            - Válido por **1 hora**
            - Uso único

            ### Autenticação Necessária
            Requer access token válido.

            ### Rate Limit
            100 requisições por minuto (limite geral).
            """)
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Email alterado com sucesso!",
                    content = @Content(schema = @Schema(implementation = MessageResponse.class))),
            @ApiResponse(responseCode = "400", description = "Tipo de token inválido",
                    content = @Content(
                            schema = @Schema(ref = "#/components/schemas/ErrorResponse"))),
            @ApiResponse(responseCode = "401", description = "Token inválido ou ausente",
                    content = @Content(
                            schema = @Schema(ref = "#/components/schemas/ErrorResponse"))),
            @ApiResponse(responseCode = "403",
                    description = "Token não pertence ao usuário autenticado",
                    content = @Content(
                            schema = @Schema(ref = "#/components/schemas/ErrorResponse"))),
            @ApiResponse(responseCode = "404", description = "Token não encontrado",
                    content = @Content(
                            schema = @Schema(ref = "#/components/schemas/ErrorResponse"))),
            @ApiResponse(responseCode = "410", description = "Token expirado",
                    content = @Content(
                            schema = @Schema(ref = "#/components/schemas/ErrorResponse")))})
    @PreAuthorize("hasAnyRole('ROLE_USER', 'ROLE_ADMIN')")
    public ResponseEntity<MessageResponse> confirmEmailChange(@AuthenticationPrincipal User user,
            @RequestParam @NotBlank(
                    message = "Token de  troca de email é um campo obrigatório") @Size(min = 36,
                            max = 36, message = "Token com formato inválido") String token) {

        String newEmail = userService.confirmEmailChange(user, token);


        return ResponseEntity
                .ok(new MessageResponse("Email alterado com sucesso para " + newEmail));
    }

}
