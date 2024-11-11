package com.example.demokeycloak.config;

import com.example.demokeycloak.auth.BasicAuthEntryPoint;
import com.example.demokeycloak.auth.KeycloakAccessDenied;
import com.example.demokeycloak.auth.KeycloakAuthEntryPoint;
import com.example.demokeycloak.auth.JwtRolesConverter;
import com.example.demokeycloak.auth.filter.CustomBasicAuthFilter;
import com.example.demokeycloak.auth.filter.CustomBearerAuthFilter;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ObservationAuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.CorsConfigurer;
import org.springframework.security.config.annotation.web.configurers.CsrfConfigurer;
import org.springframework.security.config.core.GrantedAuthorityDefaults;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtDecoders;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.JwtIssuerAuthenticationManagerResolver;
import org.springframework.security.oauth2.server.resource.web.authentication.BearerTokenAuthenticationFilter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

@Configuration
@ConditionalOnProperty(name = "application.keycloak.enabled", havingValue = "true", matchIfMissing = true)
public class SecurityConfig {
  private final JwtRolesConverter jwtRolesConverter;
  private final KeycloakAccessDenied keycloakAccessDenied;

  public SecurityConfig(JwtRolesConverter jwtRolesConverter, KeycloakAccessDenied keycloakAccessDenied) {
    this.jwtRolesConverter = jwtRolesConverter;
    this.keycloakAccessDenied = keycloakAccessDenied;
  }

  @Bean
  public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
    return http
        .csrf(CsrfConfigurer::disable)
        .cors(CorsConfigurer::disable)
        .authorizeHttpRequests(auth ->
            auth
                .requestMatchers(HttpMethod.GET, "/test/**").permitAll()
                .requestMatchers(HttpMethod.GET, "/admin/**").authenticated()
                .anyRequest().authenticated())
        .exceptionHandling(configurer ->
            configurer
                .accessDeniedHandler(keycloakAccessDenied)
        )
        .oauth2ResourceServer(oauth -> oauth.jwt(jwtConfigurer ->
            jwtConfigurer
                .jwtAuthenticationConverter(jwt -> new JwtAuthenticationToken(jwt, jwtRolesConverter.convert(jwt)))))
        .addFilterAt(new CustomBasicAuthFilter(new SimpleAuthenticationManager()), BasicAuthenticationFilter.class)
        .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
        .build();
  }

  @Bean
  public JwtDecoder jwtDecoder() {
    return JwtDecoders.fromIssuerLocation("http://localhost:8082/realms/testapi");
  }

  @Bean
  GrantedAuthorityDefaults grantedAuthorityDefaults() {
    return new GrantedAuthorityDefaults("");
  }

  @Bean
  public static PasswordEncoder basicPasswordEncoder(){
    return new BCryptPasswordEncoder();
  }

  public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
    auth.inMemoryAuthentication()
//        .passwordEncoder(basicPasswordEncoder())
        .withUser("user")
//        .password(basicPasswordEncoder().encode("password"))
        .password("password")
        .roles("ROLE_ADMIN");
  }
}
