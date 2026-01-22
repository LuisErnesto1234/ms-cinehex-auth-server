package com.test.hex.cinehex.oauth.service;

import com.test.hex.cinehex.oauth.persistence.entity.UserEntity;
import com.test.hex.cinehex.oauth.persistence.enums.Status;
import com.test.hex.cinehex.oauth.persistence.repository.UserRepository;
import lombok.RequiredArgsConstructor;

import org.springframework.security.authentication.DisabledException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Set;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class UserDetailsServiceImpl implements UserDetailsService {

    private final UserRepository userRepository;

    @Override
    @Transactional(readOnly = true) // Importante para cargar la relación Lazy/Eager de roles
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {

        // 1. Buscar en tu base de datos
        UserEntity user = userRepository.findByEmail(email)
                .orElseThrow(() -> new UsernameNotFoundException("Usuario no encontrado: " + email));

        // 2. Verificar Status (Opcional, pero recomendado)
        if (user.getStatus() != Status.ACTIVE) {
            throw new DisabledException("La cuenta está inactiva o bloqueada");
        }

        // 3. Convertir Roles a 'GrantedAuthority'
        // Spring Security espera que los roles sean Strings simples
        Set<SimpleGrantedAuthority> authorities = user.getRoles().stream()
                .map(rol -> new SimpleGrantedAuthority(rol.getName())) // "ROLE_USER"
                .collect(Collectors.toSet());

        // 4. Retornar el objeto 'User' de Spring Security
        // OJO: Aquí pasamos el email, password y roles.
        // El UUID todavía no lo pasamos aquí porque la interfaz UserDetails estándar no tiene campo ID.
        return new User(
                user.getEmail(),
                user.getPassword(),
                true, true, true, true, // enabled, accountNonExpired, etc.
                authorities
        );
    }
}
