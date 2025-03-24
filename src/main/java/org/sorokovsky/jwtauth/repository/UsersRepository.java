package org.sorokovsky.jwtauth.repository;

import org.sorokovsky.jwtauth.entity.UserEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UsersRepository extends JpaRepository<UserEntity, Long> {
    Optional<UserEntity> findByEmail(String email);

    Optional<UserEntity> findById(Long id);

    UserEntity save(UserEntity user);
}
