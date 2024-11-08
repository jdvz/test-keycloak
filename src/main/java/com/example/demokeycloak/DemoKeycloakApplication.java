package com.example.demokeycloak;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;

@SpringBootApplication
@EnableConfigurationProperties
@ConfigurationPropertiesScan
@EnableWebSecurity
public class DemoKeycloakApplication {

  public static void main(String[] args) {
    SpringApplication.run(DemoKeycloakApplication.class, args);
  }
}
