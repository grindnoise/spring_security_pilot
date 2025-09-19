package com.example.config;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Profile;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

@Component
@Profile("!prod")
@RequiredArgsConstructor
public class CustomDaoAuthenticationProvider implements AuthenticationProvider {

    private final UserDetailsService customUserDetailsService;
    private final PasswordEncoder passwordEncoder;

//    @Override
//    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
//        final var user = customUserDetailsService.loadUserByUsername(authentication.getName());
//
//        return new UsernamePasswordAuthenticationToken(user, authentication.getCredentials().toString(), user.getAuthorities());
//    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        final var user = customUserDetailsService.loadUserByUsername(authentication.getName());

        return new UsernamePasswordAuthenticationToken(user, authentication.getCredentials().toString(), user.getAuthorities());
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return (UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication));
    }
}
