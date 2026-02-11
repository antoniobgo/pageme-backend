package com.atwo.paganois.user.repositories;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import com.atwo.paganois.user.entities.Role;

@Repository
public interface RoleRepository extends JpaRepository<Role, Long> {
    public Role findByAuthority(String authority);
}
