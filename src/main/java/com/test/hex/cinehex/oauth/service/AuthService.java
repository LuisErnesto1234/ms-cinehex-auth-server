package com.test.hex.cinehex.oauth.service;

import com.test.hex.cinehex.oauth.config.RabbitMqConfig;
import com.test.hex.cinehex.oauth.dto.request.UserRegisterRequest;
import com.test.hex.cinehex.oauth.events.dto.UserRegisteredEvent;
import com.test.hex.cinehex.oauth.persistence.entity.RolEntity;
import com.test.hex.cinehex.oauth.persistence.entity.UserEntity;
import com.test.hex.cinehex.oauth.persistence.enums.Status;
import com.test.hex.cinehex.oauth.persistence.repository.RolRepository;
import com.test.hex.cinehex.oauth.persistence.repository.UserRepository;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import org.springframework.amqp.core.AmqpTemplate;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import java.util.Set;

@Slf4j
@Service
public class AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final AmqpTemplate rabbitTemplate; // <--- Usando AmqpTemplate en lugar de RabbitTemplate
    private final RolRepository rolRepository;

    // Constructor manual para poder usar @Qualifier
    public AuthService(UserRepository userRepository,
                      PasswordEncoder passwordEncoder,
                      @Qualifier("customRabbitTemplate") AmqpTemplate rabbitTemplate, RolRepository rolRepository) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.rabbitTemplate = rabbitTemplate;
        this.rolRepository = rolRepository;
    }

    @Transactional(rollbackFor = Exception.class, timeout = 5, propagation = Propagation.REQUIRED)
    public void registerUser(UserRegisterRequest request) {
        validatorUserRequest(request);

        var defaultRole = rolRepository.findByName("ROLE_USER")
                .orElseThrow(() -> new IllegalStateException("Default role not found"));

        var userEntity = UserEntity.builder()
                .email(request.email())
                .password(passwordEncoder.encode(request.password()))
                .roles(Set.of(defaultRole)) // Asignar roles por defecto si es necesario
                .status(Status.ACTIVE)
                .build();

        var userSaved = userRepository.save(userEntity);

        var event = UserRegisteredEvent.builder()
                .userId(userSaved.getId())
                .email(userSaved.getEmail())
                .build();

        // Enviar el evento al exchange usando la routing key definida
        rabbitTemplate.convertAndSend(RabbitMqConfig.EXCHANGE_NAME, RabbitMqConfig.ROUTING_KEY, event);

        log.info("User registered and event sent: {}", event);
    }

    private void validatorUserRequest(UserRegisterRequest request) {

        if (request == null ||
                request.email() == null || request.email().isBlank() ||
                request.password() == null || request.password().isBlank()) {
            throw new IllegalArgumentException("Invalid user registration request");
        }

        if (Boolean.TRUE.equals(userRepository.existsByEmail(request.email()))) {
            throw new IllegalArgumentException("El email, " + request.email() + ", ya está registrado.");
        }
    }

}
