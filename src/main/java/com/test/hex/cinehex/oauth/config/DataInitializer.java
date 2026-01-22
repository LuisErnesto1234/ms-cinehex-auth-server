package com.test.hex.cinehex.oauth.config;

import com.test.hex.cinehex.oauth.persistence.entity.RolEntity;
import com.test.hex.cinehex.oauth.persistence.repository.RolRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.CommandLineRunner;
import org.springframework.stereotype.Component;

import java.time.Instant;

@Component
@RequiredArgsConstructor
public class DataInitializer implements CommandLineRunner {

    private final RolRepository roleRepository;

    @Override
    public void run(String... args) {
        // Crear ROLE_USER si no existe
        if (roleRepository.findByName("ROLE_USER").isEmpty()) {
            roleRepository.save(RolEntity.builder()
                    .name("ROLE_USER")
                    .createdAt(Instant.now())
                    .updatedAt(Instant.now())
                    .build());
        }

        // Crear ROLE_ADMIN si no existe
        if (roleRepository.findByName("ROLE_ADMIN").isEmpty()) {
            roleRepository.save(RolEntity.builder()
                    .name("ROLE_ADMIN")
                    .createdAt(Instant.now())
                    .updatedAt(Instant.now())
                    .build());
        }
    }
}