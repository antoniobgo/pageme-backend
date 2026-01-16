package com.atwo.paganois;

import com.atwo.paganois.entities.Role;
import com.atwo.paganois.entities.User;
import com.atwo.paganois.repositories.RoleRepository;
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
    private RoleRepository roleRepository;
    
    @Autowired
    private PasswordEncoder passwordEncoder;
    
    @Override
    public void run(String... args) {
        userRepository.deleteAll();

        Role roleAdmin = new Role();
        Role roleUser = new Role();

        roleAdmin.setAuthority("ROLE_ADMIN");
        roleUser.setAuthority("ROLE_USER");

        roleRepository.save(roleAdmin);
        roleRepository.save(roleUser);

        System.out.println("✅ Roles created:");
        System.out.println("ROLE_USER");
        System.out.println("ROLE_ADMIN");

        User user = new User();
        user.setUsername("user");
        user.setPassword(passwordEncoder.encode("password"));
        user.setRole(roleUser);
        user.setEnabled(true);
        userRepository.save(user);
        
        User admin = new User();
        admin.setUsername("admin");
        admin.setPassword(passwordEncoder.encode("admin"));
        admin.setRole(roleAdmin);
        admin.setEnabled(true);
        userRepository.save(admin);
        
        System.out.println("✅ Users created:");
        System.out.println("   - user/password (ROLE_USER)");
        System.out.println("   - admin/admin (ROLE_ADMIN)");
    }
}