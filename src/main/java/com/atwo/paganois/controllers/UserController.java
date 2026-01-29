package com.atwo.paganois.controllers;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import com.atwo.paganois.dtos.UpdatePasswordRequest;
import com.atwo.paganois.dtos.UserDTO;
import com.atwo.paganois.entities.User;
import com.atwo.paganois.services.UserService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;

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

    // @PostMapping(path = "/test-password")
    // public ResponseEntity<UpdatePasswordRequest> testPassword(
    // @RequestBody UpdatePasswordRequest request) {
    // System.out.println("TEST Endpoint - Request: " + request);
    // System.out.println("newPassword: " + request.newPassword());
    // System.out.println("oldPassword: " + request.oldPassword());
    // return ResponseEntity.ok(request);
    // }

    // TODO: Terminar fluxo de troca de email
    // TODO: Decidir a melhor forma de lidar com email: deveria salvar o usuario com o email quando
    // ele se cadastra porém ainda nao confirmou o email?

    // @PatchMapping(path = "/me/email")
    // @Operation(summary = "Mudar email do usuário autenticado",
    // description = "Retorna informações do usuário logado")
    // @ApiResponses({
    // @ApiResponse(responseCode = "200",
    // description = "Email para confirmação de troca de email enviado"),
    // @ApiResponse(responseCode = "401",
    // description = "Não autenticado - Token inválido ou ausente"),
    // @ApiResponse(responseCode = "403",
    // description = "Não autorizado - Token não tem permissão adequada")})
    // @PreAuthorize("hasAnyRole('ROLE_USER', 'ROLE_ADMIN')")
    // public ResponseEntity<UserDTO> updateEmail(@AuthenticationPrincipal User user,
    // @RequestBody @Valid UpdateEmailRequest request) {
    // request.email();
    // UserDTO userResponse = userService.getAuthenticatedUserProfile(user);
    // return ResponseEntity.ok(userResponse);
    // }

}
