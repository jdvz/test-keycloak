package com.example.demokeycloak.data;

public record UserDto(
    long id,
    String login,
    String name,
    String surname,
    String email
) {
}
