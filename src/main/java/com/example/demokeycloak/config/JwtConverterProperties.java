package com.example.demokeycloak.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "jwt.auth.converter")
public record JwtConverterProperties(
    String resourceId,
    String principalAttribute
)
{}
