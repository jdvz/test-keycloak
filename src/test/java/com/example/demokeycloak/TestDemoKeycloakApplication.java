package com.example.demokeycloak;

import org.springframework.boot.SpringApplication;

public class TestDemoKeycloakApplication {

  public static void main(String[] args) {
    SpringApplication.from(DemoKeycloakApplication::main).with(TestcontainersConfiguration.class).run(args);
  }
}
