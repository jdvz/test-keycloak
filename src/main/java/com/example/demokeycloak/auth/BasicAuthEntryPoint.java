package com.example.demokeycloak.auth;

import com.example.demokeycloak.data.MessageDto;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
public class BasicAuthEntryPoint implements AuthenticationEntryPoint {

  @Override
  public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException)
      throws IOException, ServletException {
    response.addHeader("WWW-Authenticate", "Basic realm=\"%s\"".formatted("BasicTestApi"));
    response.setStatus(HttpStatus.UNAUTHORIZED.value());
    response.setContentType("application/json");

    ObjectMapper mapper = new ObjectMapper();
    mapper.writeValue(response.getWriter(), new MessageDto("error", 3));
  }
}
