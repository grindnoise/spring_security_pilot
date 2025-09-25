package com.example.config;

// For Keycloak auth server we no longer need this
//@Component
//@Profile("!prod")
//@RequiredArgsConstructor
//public class CustomDaoAuthenticationProvider implements AuthenticationProvider {
//
//    private final UserDetailsService customUserDetailsService;
//    private final PasswordEncoder passwordEncoder;
//
////    @Override
////    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
////        final var user = customUserDetailsService.loadUserByUsername(authentication.getName());
////
////        return new UsernamePasswordAuthenticationToken(user, authentication.getCredentials().toString(), user.getAuthorities());
////    }
//
//    @Override
//    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
//        final var user = customUserDetailsService.loadUserByUsername(authentication.getName());
//
//        return new UsernamePasswordAuthenticationToken(user, authentication.getCredentials().toString(), user.getAuthorities());
//    }
//
//    @Override
//    public boolean supports(Class<?> authentication) {
//        return (UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication));
//    }
//}
