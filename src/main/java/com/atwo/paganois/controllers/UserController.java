package com.atwo.paganois.controllers;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import com.atwo.paganois.dtos.ChangeEmailRequest;
import com.atwo.paganois.dtos.MessageResponse;
import com.atwo.paganois.dtos.UpdatePasswordRequest;
import com.atwo.paganois.dtos.UserDTO;
import com.atwo.paganois.entities.User;
import com.atwo.paganois.services.UserService;
import io.swagger.v3.oas.annotations.Operation;
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
    @Operation(summary = "Obter perfil do usuário autenticado",
            description = "Retorna informações do usuário logado")
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Usuário encontrado com sucesso"),
            @ApiResponse(responseCode = "401",
                    description = "Não autenticado - Token inválido ou ausente"),
            @ApiResponse(responseCode = "403",
                    description = "Não autorizado - Token não tem permissão adequada")})
    @PreAuthorize("hasAnyRole('ROLE_USER', 'ROLE_ADMIN')")
    public ResponseEntity<UserDTO> getMe(@AuthenticationPrincipal User user) {
        UserDTO userResponse = userService.getAuthenticatedUserProfile(user);
        return ResponseEntity.ok(userResponse);
    }

    @PostMapping(path = "/me/password")
    @Operation(summary = "Mudar senha do usuário autenticado",
            description = "Mudar senha do usuário autenticado")
    @ApiResponses({@ApiResponse(responseCode = "204", description = "Senha alterada com sucesso"),
            @ApiResponse(responseCode = "401",
                    description = "Não autenticado - Token inválido ou ausente"),
            @ApiResponse(responseCode = "403",
                    description = "Não autorizado - Senha atual incorreta")})
    @PreAuthorize("hasAnyRole('ROLE_USER', 'ROLE_ADMIN')")
    public ResponseEntity<Void> updatePassword(@AuthenticationPrincipal User user,
            @RequestBody UpdatePasswordRequest request) {
        userService.updatePassword(user, request.newPassword(), request.oldPassword());
        return ResponseEntity.noContent().build();
    }

    @PostMapping(path = "/me/email")
    @Operation(summary = "Solicitar mudança de email",
            description = "Envia um email de confirmação para o novo endereço. "
                    + "O email só será alterado após confirmação.")
    @ApiResponses({
            @ApiResponse(responseCode = "200",
                    description = "Solicitação aceita. Email de confirmação enviado."),
            @ApiResponse(responseCode = "400", description = "Email inválido ou já em uso"),
            @ApiResponse(responseCode = "401",
                    description = "Não autenticado - Token inválido ou ausente")})
    @PreAuthorize("hasAnyRole('ROLE_USER', 'ROLE_ADMIN')")
    public ResponseEntity<MessageResponse> requestEmailChange(@AuthenticationPrincipal User user,
            @Valid @RequestBody ChangeEmailRequest request) {

        userService.requestEmailChange(user, request.newEmail());

        return ResponseEntity.ok().body(
                new MessageResponse("Email de confirmação enviado para " + request.newEmail()));
    }

    @GetMapping(path = "/me/email/confirm")
    @Operation(summary = "Confirmar mudança de email",
            description = "Confirma a mudança de email através do token recebido por email")
    @ApiResponses({@ApiResponse(responseCode = "200", description = "Email alterado com sucesso"),
            @ApiResponse(responseCode = "400", description = "Tipo de token inválido"),
            @ApiResponse(responseCode = "403",
                    description = "Token de troca de email não pertence ao usuário autenticado"),
            @ApiResponse(responseCode = "404", description = "Token não encontrado"),
            @ApiResponse(responseCode = "410", description = "Token expirado"),
            @ApiResponse(responseCode = "401",
                    description = "Não autenticado - Token inválido ou ausente")})
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
