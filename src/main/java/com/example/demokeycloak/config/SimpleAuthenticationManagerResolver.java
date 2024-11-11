package com.example.demokeycloak.config;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationManagerResolver;

public class SimpleAuthenticationManagerResolver implements AuthenticationManagerResolver<HttpServletRequest> {
  @Override
  public AuthenticationManager resolve(HttpServletRequest context) {
    return null;
  }
}
