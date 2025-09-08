package com.example.config;

import com.example.exception_handling.CustomBasicAuthenticationEntryPoint;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.security.authentication.password.CompromisedPasswordChecker;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.password.HaveIBeenPwnedRestApiPasswordChecker;

import static org.springframework.security.config.Customizer.withDefaults;

@Profile("prod")
@Configuration
public class SecurityProdConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.csrf(AbstractHttpConfigurer::disable);
//        http.requiresChannel(requiresChannel -> requiresChannel.anyRequest().requiresSecure());
        http.redirectToHttps(withDefaults());
        http.authorizeHttpRequests(requests ->
                requests.requestMatchers(
                                "/myBalance",
                                "/myCards",
                                "/myLoans",
                                "/myAccount").authenticated()
                        .requestMatchers(
                                "/notices",
                                "/register",
                                "/contacts",
                                "/error").permitAll());
        http.formLogin(withDefaults());
        http.httpBasic(httpSecurityHttpBasicConfigurer ->
                httpSecurityHttpBasicConfigurer.authenticationEntryPoint(new CustomBasicAuthenticationEntryPoint()));
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
}
