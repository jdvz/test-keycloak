package com.example.demokeycloak.auth;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Locale;
import java.util.Map;

@Component
public class JwtRolesConverter implements Converter<Jwt, Collection<GrantedAuthority>> {
  private static final String CLIENT_ID = "application";
  private static final String CLAIM_REALM_ACCESS = "realm_access";
  private static final String CLAIM_RESOURCE_ACCESS = "resource_access";
  private static final String CLAIM_ROLES = "roles";

  @Override
  public Collection<GrantedAuthority> convert(Jwt jwt) {
    Map<String, Collection<String>> realmAccess = jwt.getClaim(CLAIM_REALM_ACCESS);
    Map<String, Map<String, Collection<String>>> resourceAccess = jwt.getClaim(CLAIM_RESOURCE_ACCESS);

    Collection<GrantedAuthority> grantedAuthorities = new ArrayList<>();

    if (realmAccess != null && !realmAccess.isEmpty()) {
      Collection<String> realmRole = realmAccess.get(CLAIM_ROLES);
      if (realmRole != null && !realmRole.isEmpty()) {
        realmRole.forEach(r -> {
          if (resourceAccess != null && !resourceAccess.isEmpty() && resourceAccess.containsKey(CLIENT_ID)) {
            resourceAccess.get(CLIENT_ID).get(CLAIM_ROLES).forEach(resourceRole -> {
              String role = String.format("%s_%s", r, resourceRole).toUpperCase(Locale.ROOT);
              grantedAuthorities.add(new SimpleGrantedAuthority(role));
            });
          } else {
            grantedAuthorities.add(new SimpleGrantedAuthority(r));
          }
        });
      }
    }

    return grantedAuthorities;
  }
}