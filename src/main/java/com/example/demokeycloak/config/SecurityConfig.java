package com.example.demokeycloak.config;

import com.example.demokeycloak.auth.BasicAuthEntryPoint;
import com.example.demokeycloak.auth.KeycloakAccessDenied;
import com.example.demokeycloak.auth.KeycloakAuthEntryPoint;
import com.example.demokeycloak.auth.JwtRolesConverter;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.CorsConfigurer;
import org.springframework.security.config.annotation.web.configurers.CsrfConfigurer;
import org.springframework.security.config.core.GrantedAuthorityDefaults;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtDecoders;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

@Configuration
@ConditionalOnProperty(name = "application.keycloak.enabled", havingValue = "true", matchIfMissing = true)
public class SecurityConfig {
  private final JwtRolesConverter jwtRolesConverter;
  private final KeycloakAuthEntryPoint keycloakAuthEntryPoint;
  private final BasicAuthEntryPoint bsicAuthEntryPoint;
  private final KeycloakAccessDenied keycloakAccessDenied;

  public SecurityConfig(JwtRolesConverter jwtRolesConverter, KeycloakAuthEntryPoint keycloakAuthEntryPoint,
      BasicAuthEntryPoint basicAuthEntryPoint, KeycloakAccessDenied keycloakAccessDenied) {
    this.jwtRolesConverter = jwtRolesConverter;
    this.keycloakAuthEntryPoint = keycloakAuthEntryPoint;
    this.bsicAuthEntryPoint = basicAuthEntryPoint;
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
        .httpBasic(AbstractHttpConfigurer::disable)
/*
        .httpBasic(basicConfigurer -> basicConfigurer
            .realmName("testApi")
            .authenticationEntryPoint(bsicAuthEntryPoint))
*/
        .addFilterAfter(new SkipBasicFilter(), BasicAuthenticationFilter.class)
        .exceptionHandling(configurer ->
            configurer
                .authenticationEntryPoint(keycloakAuthEntryPoint)
                .accessDeniedHandler(keycloakAccessDenied)
        )
        .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
//        .oauth2ResourceServer(oauth -> oauth.jwt(Customizer.withDefaults()))
        .oauth2ResourceServer(oauth -> oauth.jwt(jwtConfigurer ->
            jwtConfigurer.jwtAuthenticationConverter(jwt -> new JwtAuthenticationToken(jwt, jwtRolesConverter.convert(jwt)))))
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
