package com.example.demokeycloak.auth.filter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationManagerResolver;
import org.springframework.security.oauth2.server.resource.web.authentication.BearerTokenAuthenticationFilter;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import java.io.IOException;
import java.util.Optional;

public class CustomBearerAuthFilter extends BearerTokenAuthenticationFilter {

  public CustomBearerAuthFilter(
      AuthenticationManagerResolver<HttpServletRequest> authenticationManagerResolver) {
    super(authenticationManagerResolver);
  }

  @Override
  protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
      throws IOException, ServletException {
    String prefix = Optional.of(request)
        .map(r -> r.getHeader("authorization"))
            .map(s-> s.split("\s")[0])
                .orElse("none");
    switch (prefix) {
      case "Bearer" -> super.doFilterInternal(request, response, chain);
    }
    chain.doFilter(request, response);
  }
}
