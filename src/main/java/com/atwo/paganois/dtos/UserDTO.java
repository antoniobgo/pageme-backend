package com.atwo.paganois.dtos;

import org.springframework.security.core.userdetails.UserDetails;
import com.atwo.paganois.entities.User;

public class UserDTO {

    private Long id;
    private String username;
    private String email;
    private RoleDTO role;
    private boolean enabled = true;
    private boolean emailVerified;

    public UserDTO() {}

    public UserDTO(Long id, String username, String email, RoleDTO role, boolean enabled,
            boolean emailVerified) {
        this.id = id;
        this.username = username;
        this.email = email;
        this.role = role;
        this.enabled = enabled;
        this.emailVerified = emailVerified;
    }

    public UserDTO(User entity) {
        id = entity.getId();
        username = entity.getUsername();
        role = new RoleDTO(entity.getRole().getId(), entity.getRole().getAuthority());
        enabled = entity.isEnabled();
        email = entity.getEmail();
        emailVerified = entity.isEmailVerified();
    }

    public UserDTO(UserDetails userDetails) {
        this(UserDTO.convertToUser(userDetails));
    }

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }


    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public RoleDTO getRole() {
        return role;
    }

    public boolean isEnabled() {
        return enabled;
    }

    public boolean isEmailVerified() {
        return emailVerified;
    }

    private static User convertToUser(UserDetails userDetails) {
        if (userDetails instanceof User) {
            return (User) userDetails;
        }
        throw new IllegalArgumentException(
                "Não é possível converter " + userDetails.getClass() + " para User");
    }

    @Override
    public String toString() {
        return "User [id=" + id + ", username=" + username + ", role=" + role.getAuthority()
                + ", enabled=" + enabled + "]";
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((id == null) ? 0 : id.hashCode());
        return result;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;
        if (getClass() != obj.getClass())
            return false;
        UserDTO other = (UserDTO) obj;
        if (id == null) {
            if (other.id != null)
                return false;
        } else if (!id.equals(other.id))
            return false;
        return true;
    }


}
