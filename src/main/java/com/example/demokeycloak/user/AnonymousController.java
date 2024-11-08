package com.example.demokeycloak.user;

import com.example.demokeycloak.data.UserDto;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/test")
public class AnonymousController {
  @GetMapping(value = "/me", produces = MediaType.APPLICATION_JSON_VALUE)
  public UserDto getMe() {
    return new UserDto(1L, "janedoe", "Doe", "Jane", "jane.doe@example.com");
  }
}
