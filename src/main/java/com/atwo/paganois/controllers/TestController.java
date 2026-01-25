package com.atwo.paganois.controllers;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import io.swagger.v3.oas.annotations.tags.Tag;

@RestController
@RequestMapping("/api")
@Tag(name = "Autorização", description = "Endpoints para testes de autorização")
public class TestController {
    
    @GetMapping("/public")
    public String publicEndpoint() {
        return "This is public!";
    }
    
    @GetMapping("/user/hello")
    @PreAuthorize("hasAnyRole('USER', 'ADMIN')")
    public String userEndpoint() {
        return "Hello User!";
    }
    
    @GetMapping("/admin/hello")
    // @PreAuthorize("hasRole('ADMIN')")
    public String adminEndpoint() {
        return "Hello Admin!";
    }
}