package com.example.config;

// For Keycloak auth server we no longer need this
//@Component
//@Profile("prod")
//@RequiredArgsConstructor
//public class CustomDaoAuthenticationProdProvider implements AuthenticationProvider {
//
//    private final EazyBankUserDetailsService customUserDetailsService;
//    private final PasswordEncoder passwordEncoder;
//
//    @Override
//    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
//        final var user = customUserDetailsService.loadUserByUsername(authentication.getName());
//        final var password = authentication.getCredentials().toString();
//
//        if (!passwordEncoder.matches(password, user.getPassword())) {
//            throw new BadCredentialsException("Invalid password");
//        }
//
//        return new UsernamePasswordAuthenticationToken(user, password, user.getAuthorities());
//    }
//
//    @Override
//    public boolean supports(Class<?> authentication) {
//        return (UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication));
//    }
//}
