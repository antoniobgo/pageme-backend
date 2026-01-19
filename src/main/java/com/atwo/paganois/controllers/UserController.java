package com.atwo.paganois.controllers;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.atwo.paganois.dtos.UserDTO;
import com.atwo.paganois.exceptions.AccountDisabledException;
import com.atwo.paganois.services.CustomUserDetailsService;

@RestController
@RequestMapping(path = "/api/users")
public class UserController {

    @Autowired
    private CustomUserDetailsService userService;

    @PreAuthorize("hasAnyRole('ROLE_USER', 'ROLE_ADMIN')")
    @GetMapping(path = "/me")
    public ResponseEntity<UserDTO> getMe(@AuthenticationPrincipal UserDetails userDetails) {
        UserDTO userResponse = userService.getAuthenticatedUserProfile(userDetails);
        return ResponseEntity.ok(userResponse);
    }

}
