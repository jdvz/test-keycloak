package com.example.demokeycloak.auth.filter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import java.io.IOException;
import java.util.Optional;

public class CustomBasicAuthFilter extends BasicAuthenticationFilter {
  public CustomBasicAuthFilter(AuthenticationManager authenticationManager) {
    super(authenticationManager);
  }

  public CustomBasicAuthFilter(AuthenticationManager authenticationManager,
      AuthenticationEntryPoint authenticationEntryPoint) {
    super(authenticationManager, authenticationEntryPoint);
  }

  @Override
  protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
      throws IOException, ServletException {
    String prefix = Optional.of(request)
        .map(r -> r.getHeader("authorization"))
        .map(s -> s.split("\s")[0])
        .orElse("none");
    switch (prefix) {
      case "Basic" -> super.doFilterInternal(request, response, chain);
    }
    chain.doFilter(request, response);
  }

  @Override
  protected void onSuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response,
      Authentication authResult) throws IOException {
    super.onSuccessfulAuthentication(request, response, authResult);
  }
}
