package com.test.hex.cinehex.oauth.controller;

import com.test.hex.cinehex.oauth.persistence.entity.RolEntity;
import com.test.hex.cinehex.oauth.persistence.repository.UserRepository;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;

import java.util.List;

@Configuration
public class TokenConfig {

    @Bean
    public OAuth2TokenCustomizer<JwtEncodingContext> jwtTokenCustomizer(UserRepository userRepository) {
        return context -> {
            // Solo personalizamos si es un Access Token (no Refresh Token)
            if (OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType())) {

                Authentication principal = context.getPrincipal();

                // Buscamos al usuario por el email (que es el principal.getName())
                // Optimización: Podrías cachear esto o implementar un UserDetails personalizado que ya tenga el ID
                userRepository.findByEmail(principal.getName()).ifPresent(user -> {

                    // A. Opción Estándar: Meter el UUID en una claim extra 'uid'
                    // context.getClaims().claim("uid", user.getId().toString());

                    // B. Opción Resource Server Friendly: Sobrescribir el 'sub'
                    // Esto hace que jwt.getSubject() en el Resource Server devuelva el UUID directamente.
                    context.getClaims().claim("sub", user.getId().toString());

                    // Extra: También puedes meter los roles explícitamente si quieres
                    List<String> roles = user.getRoles().stream()
                            .map(RolEntity::getName)
                            .toList();
                    context.getClaims().claim("roles", roles);
                });
            }
        };
    }
}
