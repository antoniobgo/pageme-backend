package com.atwo.paganois.controllers;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.atwo.paganois.dtos.UserDTO;
import com.atwo.paganois.entities.User;
import com.atwo.paganois.services.UserService;

import io.swagger.v3.oas.annotations.Operation;

@RestController
@RequestMapping(path = "/api/users")
public class UserController {

    @Autowired
    private UserService userService;

    @GetMapping(path = "/me")
    @Operation(summary = "Obter perfil do usuário autenticado", description = "Retorna informações do usuário logado")
    @PreAuthorize("hasAnyRole('ROLE_USER', 'ROLE_ADMIN')")
    public ResponseEntity<UserDTO> getMe(@AuthenticationPrincipal User user) {
        UserDTO userResponse = userService.getAuthenticatedUserProfile(user);
        return ResponseEntity.ok(userResponse);
    }

}
