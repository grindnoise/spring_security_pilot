package com.example.config;

import com.example.exception_handling.CustomAccessDeniedHandler;
import com.example.exception_handling.CustomBasicAuthenticationEntryPoint;
import com.example.filter.CsrfCookieFilter;
import com.example.filter.JwtTokenGeneratorFilter;
import com.example.filter.JwtTokenValidatorFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.password.CompromisedPasswordChecker;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.password.HaveIBeenPwnedRestApiPasswordChecker;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfTokenRequestAttributeHandler;
import org.springframework.web.cors.CorsConfiguration;

import java.util.List;

@Profile("!prod")
@Configuration
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        CsrfTokenRequestAttributeHandler csrfTokenRequestAttributeHandler = new CsrfTokenRequestAttributeHandler();

        http
                .csrf(configurer -> configurer
                        .ignoringRequestMatchers("/contact", "/register", "/apiLogin")
                        .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
                        .csrfTokenRequestHandler(csrfTokenRequestAttributeHandler))
                // Force add csrf token filter

//                .addFilterBefore(new ExampleFilter(), BasicAuthenticationFilter.class)
                .addFilterAfter(new CsrfCookieFilter(), BasicAuthenticationFilter.class)
                .addFilterAfter(new JwtTokenValidatorFilter(), BasicAuthenticationFilter.class)
                .addFilterAfter(new JwtTokenGeneratorFilter(), BasicAuthenticationFilter.class)
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
                // JSESSIONID impl
//                .securityContext(securityContext -> securityContext.requireExplicitSave(false))
//                .sessionManagement(smc ->
//                                smc//.invalidSessionUrl("/invalidSession")
////                                        // Always create JSESSIONID to reuse
////                                        .sessionCreationPolicy(SessionCreationPolicy.ALWAYS)
//                                        // Limit number of opened sessions (1 - totally secure)
//                                        .maximumSessions(3)
//                        // If a user reaches max opened sessions - we can restrict logging in
////                                .maxSessionsPreventsLogin(true)
//                )
                // JWT impl
                .sessionManagement(smc -> smc.sessionCreationPolicy(SessionCreationPolicy.STATELESS))

                .authorizeHttpRequests(requests -> requests
//                        .requestMatchers("/myBalance").hasAuthority("VIEWBALANCE")
//                        .requestMatchers("/myAccount").hasAuthority("VIEWACCOUNT")
//                        .requestMatchers("/myCards").hasAuthority("VIEWCARDS")
//                        .requestMatchers("/myLoans").hasAuthority("VIEWLOANS")
                        .requestMatchers("/myBalance").hasRole("USER")
//                        .requestMatchers("/myAccount").hasAnyRole("USER", "ADMIN")
                        .requestMatchers("/myAccount").hasRole("ADMIN") // Test
                        .requestMatchers("/myCards").hasRole("USER")
                        .requestMatchers("/myLoans").hasRole("USER")
                        .requestMatchers("/user").authenticated()
                        .requestMatchers(
                                "/notices",
                                "/register",
                                "/contact",
                                "/invalidSession",
                                "/error",
                                "/apiLogin").permitAll())
                .formLogin(Customizer.withDefaults())
                .httpBasic(httpSecurityHttpBasicConfigurer ->
                        httpSecurityHttpBasicConfigurer.authenticationEntryPoint(new CustomBasicAuthenticationEntryPoint()))
                .exceptionHandling(ehc -> ehc
//            .authenticationEntryPoint(new CustomBasicAuthenticationEntryPoint())
                                .accessDeniedHandler(new CustomAccessDeniedHandler())
//                    .accessDeniedPage("/denied")
                ); // Global Exception Handling
        return http.build();
    }

    // If UserDetailsService is implemented, then it is used automatically, otherwise use one of the provided
//    @Bean
//    public UserDetailsService userDetailsService(DataSource dataSource) {
//        return new JdbcUserDetailsManager(dataSource);
//        return new InMemoryUserDetailsManager(
//                User.withUsername("user").password("{noop}EazyBytes@12345").roles("read").build(),
//                User.withUsername("admin").password("{bcrypt}$2a$12$88.f6upbBvy0okEa7OfHFuorV29qeK.sVbB9VQ6J6dWM1bW6Qef8m").roles("admin").build());
//    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

    // Api checking
    @Bean
    public CompromisedPasswordChecker compromisedPasswordChecker() {
        return new HaveIBeenPwnedRestApiPasswordChecker();
    }


    // We need to create a bean to manually call authenticate()
    @Bean
    public AuthenticationManager authenticationManager(UserDetailsService userDetailsService, PasswordEncoder passwordEncoder) {
        CustomDaoAuthenticationProvider authenticationProvider = new CustomDaoAuthenticationProvider(userDetailsService, passwordEncoder);
        ProviderManager providerManager = new ProviderManager(authenticationProvider);
        providerManager.setEraseCredentialsAfterAuthentication(false);
        return providerManager;
    }
}
