package com.test.hex.cinehex.oauth.events.dto;

import lombok.Builder;

import java.util.UUID;

@Builder
public record UserRegisteredEvent(
        UUID userId,
        String email
) {}
