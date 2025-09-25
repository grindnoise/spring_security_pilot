package com.example.config;

import com.example.exception_handling.CustomAccessDeniedHandler;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtDecoders;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfTokenRequestAttributeHandler;
import org.springframework.web.cors.CorsConfiguration;

import java.util.List;

@Profile("!prod")
@Configuration
@EnableMethodSecurity(jsr250Enabled = true, prePostEnabled = true)
public class SecurityConfig {

    // JWT oauth
    @Value("${spring.security.oauth2.resourceserver.jwt.issuer-uri}")
    private String issuerUri;

    // Opaque token props
    /*
    @Value("${spring.security.oauth2.resourceserver.opaquetoken.client-id}")
    private String clientId;

    @Value("${spring.security.oauth2.resourceserver.opaquetoken.client-secret}")
    private String clientSecret;

    @Value("${spring.security.oauth2.resourceserver.opaquetoken.introspection-uri}")
    private String introspectionUri;
    */

    // JWT oauth
    @Bean
    public JwtDecoder jwtDecoder() {
        return JwtDecoders.fromIssuerLocation(issuerUri);
    }

    // Keycloak implementation
    @Bean
    public SecurityFilterChain keycloakBasedSecurityFilterChain(HttpSecurity http) throws Exception {

        // Create JWT token converter based on custom Keycloak converter
        final var jwtAuthConverter = new JwtAuthenticationConverter();
        jwtAuthConverter.setJwtGrantedAuthoritiesConverter(new KeycloakRoleConverter());

        // Opaque token converter
        // final var opaquTokenConverter = new KeycloakRoleConverterOpaque();

        final var csrfHandler = new CsrfTokenRequestAttributeHandler();

        http
                .csrf(configurer -> configurer
                        .ignoringRequestMatchers("/contact", "/register")
                        .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
                        .csrfTokenRequestHandler(csrfHandler))
                .cors(httpSecurityCorsConfigurer ->
                        httpSecurityCorsConfigurer.configurationSource(request -> {
                            var config = new CorsConfiguration();
                            config.setAllowedOrigins(List.of("http://localhost:4200"));
                            config.setAllowedMethods(List.of("*"));
                            config.setAllowedHeaders(List.of("*"));
                            config.setAllowCredentials(true);
                            config.setMaxAge(3600L);

                            // Expose JWT headers
                            config.setExposedHeaders(List.of("Authorization"));
                            return config;
                        }))

                // JWT impl
                .sessionManagement(smc -> smc.sessionCreationPolicy(SessionCreationPolicy.STATELESS))

                .authorizeHttpRequests(requests -> requests
                        .requestMatchers("/myBalance").hasRole("USER")
                        .requestMatchers("/myAccount").hasRole("ADMIN")
                        .requestMatchers("/myCards").hasRole("USER")
                        .requestMatchers("/myLoans").hasRole("USER")
                        .requestMatchers("/user").authenticated()
                        .requestMatchers(
                                "/notices",
                                "/register",
                                "/contact",
                                "/error").permitAll())
                // JWT based
                .oauth2ResourceServer(configurer -> configurer.jwt(jwtConfigurer -> jwtConfigurer.jwtAuthenticationConverter(jwtAuthConverter)))

//                // Opaque token based
//                .oauth2ResourceServer(oauthConfigurer -> oauthConfigurer.opaqueToken(opaqueTokenConfigurer ->
//                        opaqueTokenConfigurer.authenticationConverter(opaquTokenConverter)
//                                .introspectionUri(introspectionUri)
//                                .introspectionClientCredentials(clientId, clientSecret)
//                ))
                .exceptionHandling(ehc -> ehc.accessDeniedHandler(new CustomAccessDeniedHandler()));
        return http.build();
    }
}

//    @Bean
//    // For Keycloak auth server we no longer need custom UserDetails service
/// /    public SecurityFilterChain securityFilterChain(HttpSecurity http, EazyBankUserDetailsService eazyBankUserDetailsService) throws Exception {
//    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
//        CsrfTokenRequestAttributeHandler csrfTokenRequestAttributeHandler = new CsrfTokenRequestAttributeHandler();
//
//        http
//                .csrf(configurer -> configurer
//                        .ignoringRequestMatchers("/contact", "/register", "/apiLogin")
//                        .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
//                        .csrfTokenRequestHandler(csrfTokenRequestAttributeHandler))
//                // Force add csrf token filter
//
//                // For Keycloak auth server we no longer need these filters
//                /*
//                .addFilterAfter(new CsrfCookieFilter(), BasicAuthenticationFilter.class)
//                .addFilterAfter(new JwtTokenValidatorFilter(eazyBankUserDetailsService), BasicAuthenticationFilter.class)
//                .addFilterAfter(new JwtTokenGeneratorFilter(), BasicAuthenticationFilter.class)
//                 */
//                .cors(httpSecurityCorsConfigurer ->
//                        httpSecurityCorsConfigurer.configurationSource(request -> {
//                            var config = new CorsConfiguration();
//                            config.setAllowedOrigins(List.of("http://localhost:4200"));
//                            config.setAllowedMethods(List.of("*"));
//                            config.setAllowedHeaders(List.of("*"));
//                            config.setAllowCredentials(true);
//                            config.setMaxAge(3600L);
//
//                            // Expose JWT headers
//                            config.setExposedHeaders(List.of("Authorization"));
//
//                            return config;
//                        }))
//                // JSESSIONID impl
/// /                .securityContext(securityContext -> securityContext.requireExplicitSave(false))
/// /                .sessionManagement(smc ->
/// /                                smc//.invalidSessionUrl("/invalidSession")
/// ///                                        // Always create JSESSIONID to reuse
/// ///                                        .sessionCreationPolicy(SessionCreationPolicy.ALWAYS)
/// /                                        // Limit number of opened sessions (1 - totally secure)
/// /                                        .maximumSessions(3)
/// /                        // If a user reaches max opened sessions - we can restrict logging in
/// ///                                .maxSessionsPreventsLogin(true)
/// /                )
//                // JWT impl
//                .sessionManagement(smc -> smc.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
//
//                .authorizeHttpRequests(requests -> requests
////                        .requestMatchers("/myBalance").hasAuthority("VIEWBALANCE")
////                        .requestMatchers("/myAccount").hasAuthority("VIEWACCOUNT")
////                        .requestMatchers("/myCards").hasAuthority("VIEWCARDS")
////                        .requestMatchers("/myLoans").hasAuthority("VIEWLOANS")
//                        .requestMatchers("/myBalance").hasRole("USER")
////                        .requestMatchers("/myAccount").hasAnyRole("USER", "ADMIN")
//                        .requestMatchers("/myAccount").hasRole("ADMIN") // Test
//                        .requestMatchers("/myCards").hasRole("USER")
//                        .requestMatchers("/myLoans").hasRole("USER")
//                        .requestMatchers("/user").authenticated()
//                        .requestMatchers(
//                                "/notices",
//                                "/register",
//                                "/contact",
//                                "/invalidSession",
//                                "/error",
//                                "/apiLogin").permitAll())
//                .formLogin(Customizer.withDefaults())
//                .httpBasic(httpSecurityHttpBasicConfigurer ->
//                        httpSecurityHttpBasicConfigurer.authenticationEntryPoint(new CustomBasicAuthenticationEntryPoint()))
//                .exceptionHandling(ehc -> ehc
////            .authenticationEntryPoint(new CustomBasicAuthenticationEntryPoint())
//                                .accessDeniedHandler(new CustomAccessDeniedHandler())
////                    .accessDeniedPage("/denied")
//                ); // Global Exception Handling
//        return http.build();
//    }
//
//    // For Keycloak auth server we no longer need this
//    /*
//    // If UserDetailsService is implemented, then it is used automatically, otherwise use one of the provided
//    @Bean
//    public UserDetailsService userDetailsService(DataSource dataSource) {
//        return new JdbcUserDetailsManager(dataSource);
//        return new InMemoryUserDetailsManager(
//                User.withUsername("user").password("{noop}EazyBytes@12345").roles("read").build(),
//                User.withUsername("admin").password("{bcrypt}$2a$12$88.f6upbBvy0okEa7OfHFuorV29qeK.sVbB9VQ6J6dWM1bW6Qef8m").roles("admin").build());
//    }
//
//    @Bean
//    public PasswordEncoder passwordEncoder() {
//        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
//    }
//
//    // Api checking
//    @Bean
//    public CompromisedPasswordChecker compromisedPasswordChecker() {
//        return new HaveIBeenPwnedRestApiPasswordChecker();
//    }
//
//
//    // We need to create a bean to manually call authenticate()
//    @Bean
//    public AuthenticationManager authenticationManager(UserDetailsService userDetailsService, PasswordEncoder passwordEncoder) {
//        CustomDaoAuthenticationProvider authenticationProvider = new CustomDaoAuthenticationProvider(userDetailsService, passwordEncoder);
//        ProviderManager providerManager = new ProviderManager(authenticationProvider);
//        providerManager.setEraseCredentialsAfterAuthentication(false);
//        return providerManager;
//    }
//     */
//}
