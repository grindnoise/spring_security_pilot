package com.example.config;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal;
import org.springframework.security.oauth2.server.resource.introspection.OpaqueTokenAuthenticationConverter;

import java.util.List;

public class KeycloakRoleConverterOpaque implements OpaqueTokenAuthenticationConverter {


    /**
     * Converts a successful introspection result into an authentication result.
     *
     * @param introspectedToken      the bearer token used to perform token introspection
     * @param authenticatedPrincipal the result of token introspection
     * @return an {@link Authentication} instance
     */
    @Override
    @SuppressWarnings("unchecked")
    public Authentication convert(String introspectedToken, OAuth2AuthenticatedPrincipal authenticatedPrincipal) {
        List<String> roles = authenticatedPrincipal.getAttribute("scope");
        if (roles == null && roles.isEmpty())
            return new UsernamePasswordAuthenticationToken(authenticatedPrincipal.getName(), null, AuthorityUtils.NO_AUTHORITIES);

        final var authorities = roles
                .stream()
                .map(roleName -> "ROLE_" + roleName)
                .map(SimpleGrantedAuthority::new)
                .toList();

        return new UsernamePasswordAuthenticationToken(authenticatedPrincipal.getName(), null, authorities);
    }
}
