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

    // Opaque tokens intropection
//    @Value("${spring.security.oauth2.resourceserver.opaquetoken.client-id}")
//    private String clientId;
//
//    @Value("${spring.security.oauth2.resourceserver.opaquetoken.client-secret}")
//    private String clientSecret;
//
//    @Value("${spring.security.oauth2.resourceserver.opaquetoken.introspection-uri}")
//    private String introspectionUri;


    // JWT oauth
    @Bean
    public JwtDecoder jwtDecoder() {
        return JwtDecoders.fromIssuerLocation(issuerUri);
    }

    // Keycloak implementation
    @Bean
    public SecurityFilterChain keycloakBasedSecurityFilterChain(HttpSecurity http) throws Exception {

//        // Create JWT token converter based on custom Keycloak converter
        final var jwtAuthConverter = new JwtAuthenticationConverter();
        jwtAuthConverter.setJwtGrantedAuthoritiesConverter(new KeycloakRoleConverter());

        // Opaque token converter
//         final var opaquTokenConverter = new KeycloakRoleConverterOpaque();

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
                // Using introspection
//                .oauth2ResourceServer(configurer -> configurer.opaqueToken(opaqueTokenConfigurer ->
//                        opaqueTokenConfigurer
//                                .authenticationConverter(opaquTokenConverter)
//                                .introspectionClientCredentials(clientId, clientSecret)
//                                .introspectionUri(introspectionUri)))

                .exceptionHandling(ehc -> ehc.accessDeniedHandler(new CustomAccessDeniedHandler()));
        return http.build();
    }
}

