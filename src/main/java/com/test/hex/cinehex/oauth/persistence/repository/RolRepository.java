package com.test.hex.cinehex.oauth.persistence.repository;

import com.test.hex.cinehex.oauth.persistence.entity.RolEntity;

import lombok.NonNull;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface RolRepository extends JpaRepository<@NonNull RolEntity, @NonNull Long> {
    Optional<RolEntity> findByName(String name);
}
