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

@Profile("prod")
@Configuration
@EnableMethodSecurity(jsr250Enabled = true, prePostEnabled = true)
public class SecurityProdConfig {

    @Value("${spring.security.oauth2.resourceserver.jwt.issuer-uri}")
    private String issuerUri;

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

        CsrfTokenRequestAttributeHandler csrfTokenRequestAttributeHandler = new CsrfTokenRequestAttributeHandler();

        http
                .csrf(configurer -> configurer
                        .ignoringRequestMatchers("/contact", "/register")
                        .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
                        .csrfTokenRequestHandler(csrfTokenRequestAttributeHandler))
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
                        .requestMatchers("/myAccount").hasRole("ADMIN") // Test
                        .requestMatchers("/myCards").hasRole("USER")
                        .requestMatchers("/myLoans").hasRole("USER")
                        .requestMatchers("/user").authenticated()
                        .requestMatchers(
                                "/notices",
                                "/register",
                                "/contact",
                                "/error").permitAll())
                .oauth2ResourceServer(configurer -> configurer.jwt(jwtConfigurer -> jwtConfigurer.jwtAuthenticationConverter(jwtAuthConverter)))
                .exceptionHandling(ehc -> ehc.accessDeniedHandler(new CustomAccessDeniedHandler()));
        return http.build();
    }

//    @Bean
//    // For Keycloak auth server we no longer need custom UserDetails service
////    public SecurityFilterChain securityFilterChain(HttpSecurity http, EazyBankUserDetailsService eazyBankUserDetailsService) throws Exception {
//    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
//        http
//                .csrf(configurer -> configurer
//                        .ignoringRequestMatchers("/contact", "/register")
//                        .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
//                        .csrfTokenRequestHandler(new CsrfTokenRequestAttributeHandler()))
//                // For Keycloak auth server we no longer need these filters
//                /*
//                // Force add csrf token filter
//                .addFilterAfter(new CsrfCookieFilter(), BasicAuthenticationFilter.class)
//                .addFilterAfter(new JwtTokenValidatorFilter(eazyBankUserDetailsService), BasicAuthenticationFilter.class)
//                .addFilterAfter(new JwtTokenGeneratorFilter(), BasicAuthenticationFilter.class)
//                 */
//                .cors(httpSecurityCorsConfigurer -> httpSecurityCorsConfigurer.configurationSource(request -> {
//                    var config = new CorsConfiguration();
//                    config.setAllowedOrigins(List.of("http://localhost:4200"));
//                    config.setAllowedMethods(List.of("*"));
//                    config.setAllowedHeaders(List.of("*"));
//                    config.setAllowCredentials(true);
//                    config.setMaxAge(3600L);
//
//                    // Expose JWT headers
//                    config.setExposedHeaders(List.of("Authorization"));
//
//                    return config;
//                }))
//                // Force add csrf token filter
//                .addFilterAfter(new CsrfCookieFilter(), BasicAuthenticationFilter.class)
//                .sessionManagement(smc -> smc.sessionCreationPolicy(SessionCreationPolicy.STATELESS)) // JWT
//                .redirectToHttps(withDefaults()) // Secure https
//                .authorizeHttpRequests(requests -> requests
////                        .requestMatchers("/myBalance").hasAuthority("VIEWBALANCE")
////                        .requestMatchers("/myAccount").hasAuthority("VIEWACCOUNT")
////                        .requestMatchers("/myCards").hasAuthority("VIEWCARDS")
////                        .requestMatchers("/myLoans").hasAuthority("VIEWLOANS")
//                        .requestMatchers("/myBalance").hasRole("USER")
//                        .requestMatchers("/myAccount").hasAnyRole("USER", "ADMIN")
//                        .requestMatchers("/myCards").hasRole("USER")
//                        .requestMatchers("/myLoans").hasRole("USER")
//                        .requestMatchers("/user").authenticated()
//                        .requestMatchers(
//                                "/notices",
//                                "/register",
//                                "/contact",
//                                "/invalidSession",
//                                "/error").permitAll())
//                // Default Bootstrap html login form
//                .formLogin(withDefaults())
//                .httpBasic(httpSecurityHttpBasicConfigurer ->
//                        httpSecurityHttpBasicConfigurer.authenticationEntryPoint(new CustomBasicAuthenticationEntryPoint()))
//                .exceptionHandling(ehc ->
//                                ehc.authenticationEntryPoint(new CustomBasicAuthenticationEntryPoint())
//                                        .accessDeniedHandler(new CustomAccessDeniedHandler())
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
//    }*/
}
