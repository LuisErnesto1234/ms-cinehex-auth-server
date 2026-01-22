package com.test.hex.cinehex.oauth.persistence.repository;

import com.test.hex.cinehex.oauth.persistence.entity.UserEntity;

import lombok.NonNull;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;
import java.util.UUID;

@Repository
public interface UserRepository extends JpaRepository<@NonNull UserEntity, @NonNull UUID> {
    Optional<UserEntity> findByEmail(String email);
    Boolean existsByEmail(String email);
}
