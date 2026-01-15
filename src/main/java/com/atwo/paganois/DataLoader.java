package com.atwo.paganois;

import com.atwo.paganois.entities.User;
import com.atwo.paganois.repositories.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

@Component
public class DataLoader implements CommandLineRunner {
    
    @Autowired
    private UserRepository userRepository;
    
    @Autowired
    private PasswordEncoder passwordEncoder;
    
    @Override
    public void run(String... args) {
        // Limpa dados anteriores (opcional)
        userRepository.deleteAll();
        
        // Cria usuário normal - ✅ COM ROLE_
        User user = new User();
        user.setUsername("user");
        user.setPassword(passwordEncoder.encode("password"));
        user.setRole("ROLE_USER");  // ✅ Corrigido!
        user.setEnabled(true);
        userRepository.save(user);
        
        // Cria admin - ✅ COM ROLE_
        User admin = new User();
        admin.setUsername("admin");
        admin.setPassword(passwordEncoder.encode("admin"));
        admin.setRole("ROLE_ADMIN");  // ✅ Corrigido!
        admin.setEnabled(true);
        userRepository.save(admin);
        
        System.out.println("✅ Users created:");
        System.out.println("   - user/password (ROLE_USER)");
        System.out.println("   - admin/admin (ROLE_ADMIN)");
    }
}