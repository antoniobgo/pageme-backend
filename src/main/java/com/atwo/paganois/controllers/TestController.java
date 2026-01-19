package com.atwo.paganois.controllers;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api")
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