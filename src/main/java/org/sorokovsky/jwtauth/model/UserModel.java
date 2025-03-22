package org.sorokovsky.jwtauth.model;

import lombok.*;
import org.sorokovsky.jwtauth.entity.UserEntity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.time.LocalDateTime;
import java.util.Collection;
import java.util.List;

@EqualsAndHashCode(callSuper = true)
@Data()
@NoArgsConstructor
public class UserModel extends BaseModel implements UserDetails {
    private String email;
    private String password;

    public UserModel(Long id, LocalDateTime createdAt, LocalDateTime updatedAt, String email, String password) {
        super(id, createdAt, updatedAt);
        this.email = email;
        this.password = password;
    }

    public static UserModel from(UserEntity user) {
        return new UserModel(user.getId(), user.getCreatedAt(), user.getUpdatedAt(), user.getEmail(), user.getPassword());
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return List.of();
    }

    @Override
    public String getPassword() {
        return password;
    }

    @Override
    public String getUsername() {
        return email;
    }
}
